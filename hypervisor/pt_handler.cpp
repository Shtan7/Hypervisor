#include "ept.hpp"
#include <intrin.h>
#include "common.hpp"
#include <limits>
#include <exception>
#include "invept.hpp"
#include "vmcall.hpp"
#include "x86-64.hpp"
#include "pt_handler.hpp"

namespace hh
{
  namespace ept
  {
    pt_handler::pt_handler()
    {
      is_ept_features_supported();
    }

    void pt_handler::is_ept_features_supported() const
    {
      const x86::msr::vmx_ept_vpid_cap_register_t vpid_register = x86::msr::read<x86::msr::vmx_ept_vpid_cap_register_t>();
      const x86::msr::def_type_register_t mttr_def_type = x86::msr::read<x86::msr::def_type_register_t>();

      if (!vpid_register.flags.page_walk_length_4 || !vpid_register.flags.memory_type_write_back
        || !vpid_register.flags.pde_2mb_pages)
      {
        throw std::exception{ "The processor doesn't support some of next flags:"
          "page_walk_length_4, memory_type_write_back, pde_2mb_pages.\n" };
      }

      if (!vpid_register.flags.advanced_vmexit_ept_violations_information)
      {
        throw std::exception{ "The processor doesn't report advanced VM-exit information for EPT violations.\n" };
      }

      if (!vpid_register.flags.execute_only_pages)
      {
        throw std::exception{ "The processor doesn't support execute-only pages." };
      }

      if (!mttr_def_type.flags.mtrr_enable)
      {
        throw std::exception{ "Dynamic ranges not supported.\n" };
      }

      KdPrint(("All ept related features are present.\n"));
    }

    eptp pt_handler::get_eptp() const noexcept
    {
      return ept_state_.ept_pointer;
    }

    void pt_handler::notify_all_to_invalidate_ept() const noexcept
    {
      KeIpiGenericCall([](uint64_t context) -> uint64_t
        {
          if (context == 0)
          {
            vmx::vmcall(vmx::vmcall_number::invept_all_contexts);
          }
          else
          {
            vmx::vmcall(vmx::invept_context{ context });
          }

          return 0;
        }, ept_state_.ept_pointer.flags);
    }

    void pt_handler::split_large_page(std::shared_ptr<ept::vmm::dynamic_split> pre_allocated_buff, uint64_t physical_address)
    {
      using namespace ept;

      pml2_entry* target_entry = get_pml2_entry(physical_address);

      // If this large page is not marked a large page, that means it's a pointer already.
      // That page is therefore already split.
      if (!target_entry->large_page)
      {
        return;
      }

      RtlZeroMemory(pre_allocated_buff.get(), sizeof(vmm::dynamic_split));

      pre_allocated_buff->entry = target_entry;

      pml1_entry entry_template = {};
      entry_template.read_access = 1;
      entry_template.write_access = 1;
      entry_template.execute_access = 1;
      entry_template.memory_type = target_entry->memory_type;
      entry_template.ignore_pat = target_entry->ignore_pat;
      entry_template.suppress_ve = target_entry->suppress_ve;

      __stosq(reinterpret_cast<uint64_t*>(&pre_allocated_buff->pml1[0]), entry_template.flags, vmm::pml1e_count);

      for (uint32_t entry_index = 0; entry_index < vmm::pml1e_count; entry_index++)
      {
        pre_allocated_buff->pml1[entry_index].page_frame_number = (target_entry->page_frame_number * size_2mb) / PAGE_SIZE + entry_index;
      }

      pml2_pointer new_pointer = {};
      new_pointer.write_access = 1;
      new_pointer.read_access = 1;
      new_pointer.execute_access = 1;
      new_pointer.page_frame_number = common::virtual_address_to_physical_address(&pre_allocated_buff->pml1[0]) / PAGE_SIZE;

      RtlCopyMemory(target_entry, &new_pointer, sizeof(new_pointer));
    }

    ept::pml2_entry* pt_handler::get_pml2_entry(uint64_t physical_address)
    {
      using namespace ept;

      const uint64_t directory = ADDRMASK_EPT_PML2_INDEX(physical_address);
      const uint64_t directory_pointer = ADDRMASK_EPT_PML3_INDEX(physical_address);
      const uint64_t pml4_entry = ADDRMASK_EPT_PML4_INDEX(physical_address);

      // Addresses above 512GB are invalid because it is > physical address bus width 
      if (pml4_entry > 0)
      {
        throw std::exception{ "Invalid physical address passed." };
      }

      return &ept_state_.ept_page_table->pml2[directory_pointer][directory];
    }

    pml1_entry* pt_handler::get_pml1_entry(uint64_t physical_address)
    {
      using namespace ept;

      const uint64_t directory = ADDRMASK_EPT_PML2_INDEX(physical_address);
      const uint64_t directory_pointer = ADDRMASK_EPT_PML3_INDEX(physical_address);
      const uint64_t pml4_entry = ADDRMASK_EPT_PML4_INDEX(physical_address);

      if (pml4_entry > 0)
      {
        throw std::exception{ "Invalid physical address passed." };
      }

      pml2_entry* pml2 = &ept_state_.ept_page_table->pml2[directory_pointer][directory];

      // Check to ensure the page is split 
      if (pml2->large_page)
      {
        throw std::exception{ "Page wasn't splitted. Cannot return pml1 entry." };
      }

      // Conversion to get the right page_frame_number.
      // These pointers occupy the same place in the table and are directly convertable.
      pml2_pointer* pml2_p = reinterpret_cast<pml2_pointer*>(pml2);

      // If it is, translate to the PML1 pointer 
      pml1_entry* pml1 = reinterpret_cast<pml1_entry*>(common::physical_address_to_virtual_address(pml2_p->page_frame_number * PAGE_SIZE));

      if (pml1 == nullptr)
      {
        throw std::exception{ "Invalid physical address passed." };
      }

      pml1 = &pml1[ADDRMASK_EPT_PML1_INDEX(physical_address)];

      return pml1;
    }

    void pt_handler::set_pml1_and_invalidate_tlb(pml1_entry* entry_address, pml1_entry entry_value, vmx::invept_type invalidation_type) noexcept
    {
      const common::spinlock_guard lock{ &pml1_modification_and_invalidation_lock_ };

      entry_address->flags = entry_value.flags;

      if (invalidation_type == vmx::invept_type::invept_single_context)
      {
        vmx::invept_single_context(ept_state_.ept_pointer.flags);
      }
      else
      {
        vmx::invept_all_contexts();
      }
    }

    void pt_handler::initialize_ept()
    {
      build_mttr_map();
      create_identity_page_table();

      eptp eptp = {};

      // For performance, we let the processor know it can cache the EPT.
      eptp.memory_type = static_cast<uint64_t>(memory_type::write_back);

      // We are not utilizing the 'access' and 'dirty' flag features. 
      eptp.enable_access_and_dirty_flags = false;

      /*
      Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
      see Section 28.2.2
      */
      eptp.page_walk_length = 3;

      // The physical page number of the page table we will be using 
      eptp.page_frame_number = common::virtual_address_to_physical_address(&ept_state_.ept_page_table->pml4) / PAGE_SIZE;

      // We will write the EPTP to the VMCS later 
      ept_state_.ept_pointer = eptp;
    }

    void pt_handler::setup_pml2_entry(pml2_entry* new_entry, uint64_t page_frame_number) const noexcept
    {
      /*
      Each of the 512 collections of 512 PML2 entries is setup here.
      This will, in total, identity map every physical address from 0x0 to physical address 0x8000000000 (512GB of memory)

      ((entry_group_index * vmm::pml2e_count) + entry_index) * 2MB is the actual physical address we're mapping
      */
      new_entry->page_frame_number = page_frame_number;

      // Size of 2MB page * page_frame_number == address_of_page (physical memory). 
      const uint64_t address_of_page = page_frame_number * size_2mb;

      /* To be safe, we will map the first page as UC as to not bring up any kind of undefined behavior from the
      fixed MTRR section which we are not formally recognizing (typically there is MMIO memory in the first MB).

      I suggest reading up on the fixed MTRR section of the manual to see why the first entry is likely going to need to be UC.
      */
      if (page_frame_number == 0)
      {
        new_entry->memory_type = static_cast<uint64_t>(memory_type::uncacheable);

        return;
      }

      // Default memory type is always WB for performance. 
      memory_type target_memory_type = memory_type::write_back;

      // For each MTRR range 
      for (uint64_t current_mttr_range = 0; current_mttr_range < ept_state_.number_of_enabled_memory_ranges; current_mttr_range++)
      {
        // If this page's address is below or equal to the max physical address of the range 
        if (address_of_page <= ept_state_.memory_ranges[current_mttr_range].physical_end_address)
        {
          // And this page's last address is above or equal to the base physical address of the range 
          if ((address_of_page + ept::size_2mb - 1) >= ept_state_.memory_ranges[current_mttr_range].physical_base_address)
          {
            /* If we're here, this page fell within one of the ranges specified by the variable MTRRs
            Therefore, we must mark this page as the same cache type exposed by the MTRR
            */
            target_memory_type = ept_state_.memory_ranges[current_mttr_range].memory_type;

            // 11.11.4.1 MTRR Precedences 
            if (target_memory_type == ept::memory_type::uncacheable)
            {
              // If this is going to be marked uncacheable, then we stop the search as UC always takes precedent. 
              break;
            }
          }
        }
      }

      // Finally, commit the memory type to the entry. 
      new_entry->memory_type = static_cast<uint64_t>(target_memory_type);
    }

    void pt_handler::create_identity_page_table()
    {
      // Allocate address anywhere in the OS's memory space
      const PHYSICAL_ADDRESS max_size = { .QuadPart = static_cast<long long>((std::numeric_limits<unsigned long long>::max)()) };

      // Allocate all paging structures as 4KB aligned pages 
      auto* page_table = reinterpret_cast<vmm::page_table*>(MmAllocateContiguousMemory((sizeof(vmm::page_table)
        / PAGE_SIZE) * PAGE_SIZE, max_size));

      if (page_table == nullptr)
      {
        throw std::exception{ "Failed to allocate a page table." };
      }

      // Zero out all entries to ensure all unused entries are marked Not Present 
      RtlZeroMemory(page_table, sizeof(vmm::page_table));

      // Mark the first 512GB PML4 entry as present, which allows us to manage up to 512GB of discrete paging structures. 
      page_table->pml4[0].page_frame_number = common::virtual_address_to_physical_address(&page_table->pml3[0]) / PAGE_SIZE;
      page_table->pml4[0].read_access = 1;
      page_table->pml4[0].write_access = 1;
      page_table->pml4[0].execute_access = 1;

      /* Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry */

      // Ensure stack memory is cleared
      pml3_pointer rwx_template = {};

      // Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries 
      // Using the same method as SimpleVisor for copying each entry using intrinsics. 
      rwx_template.read_access = 1;
      rwx_template.write_access = 1;
      rwx_template.execute_access = 1;

      // Copy the template into each of the 512 PML3 entry slots 
      __stosq(reinterpret_cast<uint64_t*>(&page_table->pml3[0]), rwx_template.flags, vmm::pml3e_count);

      for (uint64_t entry_index = 0; entry_index < vmm::pml3e_count; entry_index++)
      {
        // Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
        // NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
        page_table->pml3[entry_index].page_frame_number = common::virtual_address_to_physical_address(&page_table->pml2[entry_index][0]) / PAGE_SIZE;
      }

      pml2_entry pml2_template = {};

      pml2_template.read_access = 1;
      pml2_template.write_access = 1;
      pml2_template.execute_access = 1;

      // We are using 2MB large pages, so we must mark this 1 here. 
      pml2_template.large_page = 1;

      /* For each collection of 512 PML2 entries (512 collections * 512 entries per collection), mark it RWX using the same template above.
      This marks the entries as "Present" regardless of if the actual system has memory at this region or not. We will cause a fault in our
      EPT handler if the guest access a page outside a usable range, despite the EPT frame being present here.
      */
      __stosq(reinterpret_cast<uint64_t*>(&page_table->pml2[0]), pml2_template.flags, vmm::pml3e_count * vmm::pml2e_count);

      // For each of the 512 collections of 512 2MB PML2 entries 
      for (uint64_t entry_group_index = 0; entry_group_index < vmm::pml3e_count; entry_group_index++)
      {
        for (uint64_t entry_index = 0; entry_index < vmm::pml2e_count; entry_index++)
        {
          setup_pml2_entry(&page_table->pml2[entry_group_index][entry_index], entry_group_index * vmm::pml2e_count + entry_index);
        }
      }

      ept_state_.ept_page_table = page_table;
    }

    void pt_handler::build_mttr_map() noexcept
    {
      const x86::msr::mttr_capabilities_register_t mttr_cap = x86::msr::read<x86::msr::mttr_capabilities_register_t>();

      x86::msr::mtrr_physbase_register_t current_phys_base;
      x86::msr::mtrr_physmask_register_t current_phys_mask;
      mttr_range_descriptor descriptor;

      for (uint32_t current_register = 0; current_register < mttr_cap.flags.variable_range_count; current_register++)
      {
        // For each dynamic register pair
        current_phys_base = x86::msr::read<x86::msr::mtrr_physbase_register_t>(current_register * 2);
        current_phys_mask = x86::msr::read<x86::msr::mtrr_physmask_register_t>(current_register * 2);

        // Is the range enabled?
        if (current_phys_mask.flags.valid)
        {
          // We only need to read these once because the ISA dictates that MTRRs are to be synchronized between all processors
          // during BIOS initialization.
          descriptor = ept_state_.memory_ranges[ept_state_.number_of_enabled_memory_ranges++];

          // Calculate the base address in bytes
          descriptor.physical_base_address = current_phys_base.flags.page_frame_number * PAGE_SIZE;

          // Calculate the total size of the range
          // The lowest bit of the mask that is set to 1 specifies the size of the range
          uint32_t number_of_bits_in_mask;
          _BitScanForward64(reinterpret_cast<ULONG*>(&number_of_bits_in_mask), current_phys_mask.flags.page_frame_number * PAGE_SIZE);

          // Size of the range in bytes + Base Address
          descriptor.physical_end_address = descriptor.physical_base_address + ((1ull << number_of_bits_in_mask) - 1ull);

          // Memory Type (cacheability attributes)
          descriptor.memory_type = static_cast<memory_type>(current_phys_base.flags.type);

          if (descriptor.memory_type == memory_type::write_back)
          {
            /* This is already our default, so no need to store this range.
            * Simply 'free' the range we just wrote. */
            ept_state_.number_of_enabled_memory_ranges--;
          }

          KdPrint(("MTRR Range: Base=0x%llx End=0x%llx Type=0x%x\n", descriptor.physical_base_address, descriptor.physical_end_address, descriptor.memory_type));
        }
      }

      KdPrint(("Total MTRR Ranges Committed: %d\n", ept_state_.number_of_enabled_memory_ranges));
    }
  }

  ept::pt_handler::~pt_handler() noexcept
  {
    if (ept_state_.ept_page_table)
    {
      MmFreeContiguousMemory(ept_state_.ept_page_table);
    }
  }
}
