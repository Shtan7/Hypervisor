#pragma once
#include <stdint.h>
#include "common.hpp"
#include <intrin.h>

namespace hh
{
  namespace ept
  {
    struct hooked_page_detail;
  }

  namespace vmx
  {
    inline constexpr uint32_t vmcs_size = 4096;
    inline constexpr uint32_t vmxon_size = 4096;
    inline constexpr uint32_t vmm_stack_size = 0x8000;

    enum class vmcs_fields : uint32_t
    {
      virtual_processor_id = 0x00000000,
      posted_intr_notification_vector = 0x00000002,
      eptp_index = 0x00000004,
#define GUEST_SEG_SELECTOR(sel) (GUEST_ES_SELECTOR + (sel) * 2) /* ES ... GS */
      guest_es_selector = 0x00000800,
      guest_cs_selector = 0x00000802,
      guest_ss_selector = 0x00000804,
      guest_ds_selector = 0x00000806,
      guest_fs_selector = 0x00000808,
      guest_gs_selector = 0x0000080a,
      guest_ldtr_selector = 0x0000080c,
      guest_tr_selector = 0x0000080e,
      guest_intr_status = 0x00000810,
      guest_pml_index = 0x00000812,
      host_es_selector = 0x00000c00,
      host_cs_selector = 0x00000c02,
      host_ss_selector = 0x00000c04,
      host_ds_selector = 0x00000c06,
      host_fs_selector = 0x00000c08,
      host_gs_selector = 0x00000c0a,
      host_tr_selector = 0x00000c0c,
      io_bitmap_a = 0x00002000,
      io_bitmap_b = 0x00002002,
      msr_bitmap = 0x00002004,
      vm_exit_msr_store_addr = 0x00002006,
      vm_exit_msr_load_addr = 0x00002008,
      vm_entry_msr_load_addr = 0x0000200a,
      pml_address = 0x0000200e,
      tsc_offset = 0x00002010,
      virtual_apic_page_addr = 0x00002012,
      apic_access_addr = 0x00002014,
      pi_desc_addr = 0x00002016,
      vm_function_control = 0x00002018,
      ept_pointer = 0x0000201a,
      eoi_exit_bitmap0 = 0x0000201c,
#define EOI_EXIT_BITMAP(n) (EOI_EXIT_BITMAP0 + (n) * 2) /* n = 0...3 */
      eptp_list_addr = 0x00002024,
      vmread_bitmap = 0x00002026,
      vmwrite_bitmap = 0x00002028,
      virt_exception_info = 0x0000202a,
      xss_exit_bitmap = 0x0000202c,
      tsc_multiplier = 0x00002032,
      guest_physical_address = 0x00002400,
      vmcs_link_pointer = 0x00002800,
      guest_ia32_debugctl = 0x00002802,
      guest_ia32_debugctl_high = 0x00002803,
      guest_pat = 0x00002804,
      guest_efer = 0x00002806,
      guest_perf_global_ctrl = 0x00002808,
      guest_pdpte0 = 0x0000280a,
#define GUEST_PDPTE(n) (GUEST_PDPTE0 + (n) * 2) /* n = 0...3 */
      guest_bndcfgs = 0x00002812,
      host_pat = 0x00002c00,
      host_efer = 0x00002c02,
      host_perf_global_ctrl = 0x00002c04,
      pin_based_vm_exec_control = 0x00004000,
      cpu_based_vm_exec_control = 0x00004002,
      exception_bitmap = 0x00004004,
      page_fault_error_code_mask = 0x00004006,
      page_fault_error_code_match = 0x00004008,
      cr3_target_count = 0x0000400a,
      vm_exit_controls = 0x0000400c,
      vm_exit_msr_store_count = 0x0000400e,
      vm_exit_msr_load_count = 0x00004010,
      vm_entry_controls = 0x00004012,
      vm_entry_msr_load_count = 0x00004014,
      vm_entry_intr_info = 0x00004016,
      vm_entry_exception_error_code = 0x00004018,
      vm_entry_instruction_len = 0x0000401a,
      tpr_threshold = 0x0000401c,
      secondary_vm_exec_control = 0x0000401e,
      ple_gap = 0x00004020,
      ple_window = 0x00004022,
      vm_instruction_error = 0x00004400,
      vm_exit_reason = 0x00004402,
      vm_exit_intr_info = 0x00004404,
      vm_exit_intr_error_code = 0x00004406,
      idt_vectoring_info = 0x00004408,
      idt_vectoring_error_code = 0x0000440a,
      vm_exit_instruction_len = 0x0000440c,
      vmx_instruction_info = 0x0000440e,
#define GUEST_SEG_LIMIT(sel) (GUEST_ES_LIMIT + (sel) * 2) /* ES ... GS */
      guest_es_limit = 0x00004800,
      guest_cs_limit = 0x00004802,
      guest_ss_limit = 0x00004804,
      guest_ds_limit = 0x00004806,
      guest_fs_limit = 0x00004808,
      guest_gs_limit = 0x0000480a,
      guest_ldtr_limit = 0x0000480c,
      guest_tr_limit = 0x0000480e,
      guest_gdtr_limit = 0x00004810,
      guest_idtr_limit = 0x00004812,
#define GUEST_SEG_AR_BYTES(sel) (GUEST_ES_AR_BYTES + (sel) * 2) /* ES ... GS */
      guest_es_ar_bytes = 0x00004814,
      guest_cs_ar_bytes = 0x00004816,
      guest_ss_ar_bytes = 0x00004818,
      guest_ds_ar_bytes = 0x0000481a,
      guest_fs_ar_bytes = 0x0000481c,
      guest_gs_ar_bytes = 0x0000481e,
      guest_ldtr_ar_bytes = 0x00004820,
      guest_tr_ar_bytes = 0x00004822,
      guest_interruptibility_info = 0x00004824,
      guest_activity_state = 0x00004826,
      guest_smbase = 0x00004828,
      guest_sysenter_cs = 0x0000482a,
      guest_preemption_timer = 0x0000482e,
      host_sysenter_cs = 0x00004c00,
      cr0_guest_host_mask = 0x00006000,
      cr4_guest_host_mask = 0x00006002,
      cr0_read_shadow = 0x00006004,
      cr4_read_shadow = 0x00006006,
      cr3_target_value0 = 0x00006008,
      cr3_target_value1 = 0x0000600a,
      cr3_target_value2 = 0x0000600c,
      cr3_target_value3 = 0x0000600e,
      exit_qualification = 0x00006400,
      guest_linear_address = 0x0000640a,
      guest_cr0 = 0x00006800,
      guest_cr3 = 0x00006802,
      guest_cr4 = 0x00006804,
#define GUEST_SEG_BASE(sel) (GUEST_ES_BASE + (sel) * 2) /* ES ... GS */
      guest_es_base = 0x00006806,
      guest_cs_base = 0x00006808,
      guest_ss_base = 0x0000680a,
      guest_ds_base = 0x0000680c,
      guest_fs_base = 0x0000680e,
      guest_gs_base = 0x00006810,
      guest_ldtr_base = 0x00006812,
      guest_tr_base = 0x00006814,
      guest_gdtr_base = 0x00006816,
      guest_idtr_base = 0x00006818,
      guest_dr7 = 0x0000681a,
      guest_rsp = 0x0000681c,
      guest_rip = 0x0000681e,
      guest_rflags = 0x00006820,
      guest_pending_dbg_exceptions = 0x00006822,
      guest_sysenter_esp = 0x00006824,
      guest_sysenter_eip = 0x00006826,
      host_cr0 = 0x00006c00,
      host_cr3 = 0x00006c02,
      host_cr4 = 0x00006c04,
      host_fs_base = 0x00006c06,
      host_gs_base = 0x00006c08,
      host_tr_base = 0x00006c0a,
      host_gdtr_base = 0x00006c0c,
      host_idtr_base = 0x00006c0e,
      host_sysenter_esp = 0x00006c10,
      host_sysenter_eip = 0x00006c12,
      host_rsp = 0x00006c14,
      host_rip = 0x00006c16,
    };

    struct vmxoff_state_t
    {
      bool is_vmxoff_executed;					    // Shows whether the VMXOFF executed or not
      uint64_t  guest_rip;							// Rip address of guest to return
      uint64_t  guest_rsp;							// Rsp address of guest to return
    };

    struct virtual_machihe_state_t
    {
      uint8_t is_on_vmx_root_mode;										// Detects whether the current logical core is on Executing on VMX Root Mode
      uint8_t increment_rip;											// Checks whether it has to redo the previous instruction or not (it used mainly in Ept routines)
      uint8_t has_launched;											    // Indicate whether the core is virtualized or not
      uint64_t vmxon_region_physical_address;							// Vmxon region physical address
      void* vmxon_region_virtual_address;							    // VMXON region virtual address
      uint64_t vmcs_region_physical_address;							// VMCS region physical address
      void* vmcs_region_virtual_address;								// VMCS region virtual address
      uint8_t* vmm_stack;												// Stack for VMM in VM-Exit State
      void* msr_bitmap_virtual_address;									// Msr Bitmap Virtual Address
      uint64_t msr_bitmap_physical_address;								// Msr Bitmap Physical Address
      vmxoff_state_t vmxoff_state;									    // Shows the vmxoff state of the guest
      ept::hooked_page_detail* mtf_ept_hook_restore_point;               // It shows the detail of the hooked paged that should be restore in MTF vm-exit
    };

    struct exception_bitmap
    {
      union
      {
        uint32_t flags;

        struct
        {
          uint32_t divide_error                : 1;
          uint32_t debug                       : 1;
          uint32_t nmi_interrupt               : 1;
          uint32_t breakpoint                  : 1;
          uint32_t overflow                    : 1;
          uint32_t bound                       : 1;
          uint32_t invalid_opcode              : 1;
          uint32_t device_not_available        : 1;
          uint32_t double_fault                : 1;
          uint32_t coprocessor_segment_overrun : 1;
          uint32_t invalid_tss                 : 1;
          uint32_t segment_not_present         : 1;
          uint32_t stack_segment_fault         : 1;
          uint32_t general_protection          : 1;
          uint32_t page_fault                  : 1;
          uint32_t reserved                    : 1;
          uint32_t x87_floating_point_error    : 1;
          uint32_t alignment_check             : 1;
          uint32_t machine_check               : 1;
          uint32_t simd_floating_point_error   : 1;
          uint32_t virtualization_exception    : 1;
        };
      };
    };

    template <typename T>
    union u64_t
    {
      static_assert(sizeof(T) <= sizeof(uint64_t));
      static_assert(std::is_trivial_v<T>);

      uint64_t as_uint64_t;
      T        as_value;
    };

    enum class error_code
    {
      success            = 0,
      failed_with_status = 1,
      failed             = 2
    };

    template<class T>
    inline error_code vmread(vmx::vmcs_fields vmcs_field, T& value)
    {
      common::u64_t<T> u = {};

      auto result = static_cast<error_code>(__vmx_vmread(static_cast<uint64_t>(vmcs_field), &u.as_uint64_t));

      value = u.as_value;

      return result;
    }

    template <typename T>
    inline error_code vmwrite(vmx::vmcs_fields vmcs_field, T value) noexcept
    {
      common::u64_t<T> u = { .as_value = value };

      return static_cast<error_code>(__vmx_vmwrite(static_cast<uint64_t>(vmcs_field), u.as_uint64_t));
    }
  }
}
