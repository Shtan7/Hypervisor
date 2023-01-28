#pragma once
#include "hooking.hpp"
#include "globals.hpp"
#include "ept.hpp"
#include <intrin.h>
#include "vmcall.hpp"
#include "invept.hpp"
#include "ept_handler.hpp"
#include "vcpu.hpp"
#include <ntimage.h>
#include <ranges>
#include "x86-64.hpp"
#include "win.hpp"

namespace hh::hook
{
  void* get_address_by_ssdt(ssdt_numbers ssdt_function_number_, bool is_win32k, void* pe_base)
  {
    static uint64_t nt_table = 0;
    static uint64_t win32k_table = 0;

    const auto ssdt_function_number = static_cast<uint32_t>(ssdt_function_number_);
    const auto* dos_header = static_cast<const IMAGE_DOS_HEADER*>(pe_base);
    const auto* nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>((reinterpret_cast<uint64_t>(pe_base) + dos_header->e_lfanew));
    char* target_address_of_function = nullptr;

    if (nt_table == 0)
    {
      auto* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<uint64_t>(nt_header) + sizeof(IMAGE_NT_HEADERS));

      for (int j = 0; j < nt_header->FileHeader.NumberOfSections; j++)
      {
        if (section[j].Characteristics & IMAGE_SCN_CNT_CODE
          && section[j].Characteristics & IMAGE_SCN_MEM_EXECUTE
          && !(section[j].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
          // find address of KiSystemServiceRepeat that contains 'lea r11, KeServiceDescriptorTableShadow'
          target_address_of_function = reinterpret_cast<char*>(
            find_pattern(reinterpret_cast<char*>(section[j].VirtualAddress) + reinterpret_cast<uint64_t>(pe_base),
                         section[j].Misc.VirtualSize, patterns::ssdt_shadow_table.pattern, patterns::ssdt_shadow_table.mask));

          if (target_address_of_function != nullptr)
          {
            break;
          }
        }
      }

      if (target_address_of_function == nullptr)
      {
        throw std::exception{ "Cannot find address of ssdt table." };
      }

      target_address_of_function += 0x3; // offset to relative address from 'lea r11, KeServiceDescriptorTableShadow'
      long relative_offset = *reinterpret_cast<long*>(target_address_of_function);
      target_address_of_function += relative_offset; // add rip relative offset
      target_address_of_function += 4; // rip relative offset computes from the end of opcode

      nt_table = reinterpret_cast<uint64_t>(target_address_of_function);
      win32k_table = nt_table + 0x20;  // currently offset is 0x20. You can find it with windbg and 'x win32k!W32pServiceTable' command. It shows current table address and
      // if you look at 'x nt!KeServiceDescriptorTableShadow' you see W32pServiceTable address below.

      /* ATTENTION! Your signatures and offsets may differ or may not. You must obtain your signatures with your
        Windows version if you want to use this code. */
    }

    const SSDTStruct* ssdt = reinterpret_cast<SSDTStruct*>(is_win32k ? win32k_table : nt_table);
    const uint64_t ssdt_base = reinterpret_cast<uint64_t>(ssdt->pServiceTable);

    if (ssdt_base == 0)
    {
      throw std::exception{ "SSDT data corrupted." };
    }

    target_address_of_function = reinterpret_cast<char*>((ssdt->pServiceTable[ssdt_function_number] >> 4) + ssdt_base);

    if (target_address_of_function == nullptr)
    {
      throw std::exception{ "Got nullptr from SSDT entry." };
    }

    return target_address_of_function;
  }

  void* find_pattern(void* start_address, uint64_t size_of_scan_section, std::string_view pattern, std::string_view mask) noexcept
  {
    for (uint32_t i = 0; i < size_of_scan_section; i++)
    {
      bool found = true;

      for (uint32_t j = 0; j < mask.size(); j++)
      {
        found &= (mask[j] == '?' || pattern[j] == *(static_cast<const char*>(start_address) + j + i));
      }

      if (found)
      {
        return static_cast<char*>(start_address) + i;
      }
    }

    return nullptr;
  }

  hook_context::hook_context(x86::cr3_t cr3) noexcept :
    target_address_{}, hook_function_{},
      orig_function_{}, old_cr3_{ x86::read<x86::cr3_t>() }, attributes{}
  {
    if(cr3.all != 0)
    {
      x86::write<x86::cr3_t>(cr3);
    }
  }

  hook_context::self& hook_context::set_target_address(void* target_address) noexcept
  {
    target_address_ = static_cast<uint8_t*>(target_address);
    return *this;
  }

  hook_context::self& hook_context::set_functions(void* hook_function, void** orig_function) noexcept
  {
    hook_function_ = hook_function;
    orig_function_ = orig_function;

    return *this;
  }

  hook_context::~hook_context() noexcept
  {
    x86::write<x86::cr3_t>(old_cr3_);
  }

  hook_context::self& hook_context::set_read() noexcept
  {
    attributes.read = 1;
    return *this;
  }

  hook_context::self& hook_context::set_write() noexcept
  {
    attributes.write = 1;
    return *this;
  }

  hook_context::self& hook_context::set_exec() noexcept
  {
    attributes.exec = 1;
    return *this;
  }

  void hook_builder::write_absolute_jmp(uint8_t* target_buffer, uint64_t where_to_jmp) const noexcept
  {
#pragma warning(push)
#pragma warning(disable : 4309)

    target_buffer[0] = 0xFF;
    target_buffer[1] = 0x25; // jmp qword ptr [where_to_jump]
    int32_t relative_offset = {};
    *reinterpret_cast<int32_t*>(&target_buffer[2]) = relative_offset;
    *reinterpret_cast<uint64_t*>(&target_buffer[6]) = where_to_jmp;

#pragma warning(pop)
  }

  void hook_builder::write_absolute_ret(uint8_t* target_buffer, uint64_t where_to_jmp) const noexcept
  {
#pragma warning(push)
#pragma warning(disable : 4309)

    uint32_t part_1 = (where_to_jmp & 0xFFFFFFFF00000000) >> 32;
    uint32_t part_2 = where_to_jmp & 0x00000000FFFFFFFF;

    target_buffer[0] = 0x48;
    target_buffer[1] = 0x83;
    target_buffer[2] = 0xEC;
    target_buffer[3] = 0x08; // sub rsp, 8
    target_buffer[4] = 0xC7;
    target_buffer[5] = 0x04;
    target_buffer[6] = 0x24; // mov dword ptr [rsp], part_2

    *reinterpret_cast<uint32_t*>(&target_buffer[7]) = part_2; // mov [rsp], dword_part_2

    target_buffer[11] = 0xC7;
    target_buffer[12] = 0x44;
    target_buffer[13] = 0x24;
    target_buffer[14] = 0x04; // mov dwrod ptr [rsp+4], part_1

    *reinterpret_cast<uint32_t*>(&target_buffer[15]) = part_1; // mov [rsp+4], dword_part_1

    target_buffer[19] = 0xC3; // ret

#pragma warning(pop)
  }

  void hook_builder::hook_instruction_in_memory(ept::hooked_page_detail* hooked_page, hook_context* context)
  {
    using namespace ept;
    constexpr uint32_t hook_size = 20;

    const uint32_t offset_into_page = ADDRMASK_EPT_PML1_OFFSET(reinterpret_cast<uint64_t>(context->target_address_));
    const uint32_t size_of_hooked_instructions = lde_.get_instructions_length(context->target_address_, hook_size);

    if ((offset_into_page + size_of_hooked_instructions) > (PAGE_SIZE - 1))
    {
      throw std::exception{ "Function extends past a page boundary. We just don't have the technology to solve this." };
    }

    hooked_page->trampoline = std::make_shared<uint8_t[]>(common::max_trampoline_size);

    // Copy the trampoline instructions in.
    RtlCopyMemory(hooked_page->trampoline.get(), context->target_address_, size_of_hooked_instructions);

    // Add the absolute jump back to the original function.
    write_absolute_jmp(hooked_page->trampoline.get() + size_of_hooked_instructions,
                       reinterpret_cast<uint64_t>(context->target_address_ + size_of_hooked_instructions));

    // Let the hook function call the original function 
    *context->orig_function_ = hooked_page->trampoline.get();

    // Write the absolute jump to our shadow page memory to jump to our hook.
    write_absolute_ret(&hooked_page->fake_page_contents[offset_into_page], reinterpret_cast<uint64_t>(context->hook_function_));
  }

  void hook_builder::ept_hook_internal(hook_context* context)
  {
    using namespace ept;
    const uint32_t pages_number_in_list_before = hooked_pages_list_.size();

    void* virtual_target = PAGE_ALIGN(context->target_address_);
    const uint64_t physical_address = common::virtual_address_to_physical_address(virtual_target);

    try
    {
      if (!physical_address)
      {
        throw std::exception{ "Target address couldn't be mapped to physical memory." };
      }

      std::shared_ptr<vmm::dynamic_split> target_buff = std::make_shared<vmm::dynamic_split>();

      globals::pt_handler->split_large_page(target_buff, physical_address);

      pml1_entry* target_page = globals::pt_handler->get_pml1_entry(physical_address);

      // Save the original permissions of the page 
      pml1_entry changed_entry = *target_page;

      changed_entry.read_access = context->attributes.read;
      changed_entry.write_access = context->attributes.write;

      hooked_pages_list_[physical_address] = {};
      hooked_page_detail& hooked_page = hooked_pages_list_.find(physical_address)->second;

      hooked_page.dynamic_split = target_buff;
      hooked_page.virtual_address = context->target_address_;
      hooked_page.physical_base_address = physical_address;
      hooked_page.physical_base_address_of_fake_page_contents = common::virtual_address_to_physical_address(
        &hooked_page.fake_page_contents[0]) / PAGE_SIZE;
      hooked_page.entry_address = target_page;
      hooked_page.original_entry = *target_page;

      if (context->attributes.exec)
      {
        // Show that entry has hidden hooks for execution
        hooked_page.is_execution_hook = true;

        // In execution hook, we have to make sure to unset read, write because
        // an EPT violation should occur for these cases and we can swap the original page
        changed_entry.read_access = 0;
        changed_entry.write_access = 0;
        changed_entry.execute_access = 1;

        // Also set the current pfn to fake page
        changed_entry.page_frame_number = hooked_page.physical_base_address_of_fake_page_contents;

        RtlCopyBytes(&hooked_page.fake_page_contents, virtual_target, PAGE_SIZE);

        hook_instruction_in_memory(&hooked_page, context);
      }

      hooked_page.changed_entry = changed_entry;

      if (!globals::vcpus[KeGetCurrentProcessorNumber()].launch_status())
      {
        target_page->flags = changed_entry.flags;
      }
      else
      {
        globals::pt_handler->set_pml1_and_invalidate_tlb(target_page, changed_entry, vmx::invept_type::invept_single_context);
      }
    }
    catch (std::exception& e)
    {
      KdPrint(("Caught exception in hook installation process. %s\n", e.what()));

      if (pages_number_in_list_before != hooked_pages_list_.size())
      {
        hooked_pages_list_.erase(physical_address);
      }
    }
  }
    
  void hook_builder::ept_hook(hook_context& context)
  {
    if (context.attributes.all == 0)
    {
      throw std::exception{ "Incorrect page hook mask." };
    }

    const uint32_t core_index = KeGetCurrentProcessorNumber();

    if(globals::vcpus[core_index].launch_status())
    {
      if (globals::vcpus[core_index].vmx_root_status())
      {
        ept_hook_internal(&context);
      }
      else
      {
        vmx::vmcall(&context);
        globals::pt_handler->notify_all_to_invalidate_ept();
      }
    }
    else
    {
      ept_hook_internal(&context);
    }
  }

  void hook_builder::unhook_all_pages()
  {
    if (!globals::vcpus[KeGetCurrentProcessorNumber()].vmx_root_status())
    {
      throw std::exception{ "Must be called in root mode." };
    }

    for (auto& page : hooked_pages_list_ | std::views::values)
    {
      globals::pt_handler->set_pml1_and_invalidate_tlb(page.entry_address, page.original_entry, vmx::invept_type::invept_single_context);
    }

    hooked_pages_list_.clear();
  }

  void hook_builder::unhook_single_page(uint64_t physical_address)
  {
    if (!globals::vcpus[KeGetCurrentProcessorNumber()].vmx_root_status())
    {
      throw std::exception{ "Must be called in root mode." };
    }

    auto& target_page = hooked_pages_list_.at(physical_address);

    globals::pt_handler->set_pml1_and_invalidate_tlb(target_page.entry_address, target_page.original_entry,
                                                     vmx::invept_type::invept_single_context);

    hooked_pages_list_.erase(physical_address);
  }

  ept::hooked_page_detail* hook_builder::get_hooked_page_info(uint64_t guest_physical_address) noexcept
  {
    auto& page = hooked_pages_list_.at(guest_physical_address);
    return &page;
  }
}
