#pragma once
#include <stdint.h>

namespace hh
{
  namespace x86
  {
    struct rflags_t;

    namespace msr
    {
      inline constexpr uint32_t reserved_msr_range_low = 0x40000000;
      inline constexpr uint32_t reserved_msr_range_hi = 0x400000f0;

      struct apic_base
      {
        static constexpr uint32_t msr_id = 0x01b;
        using result_type = uint64_t;
      };

      struct feature_control
      {
        static constexpr uint32_t msr_id = 0x03a;
        using result_type = uint64_t;
      };

      struct vmx_basic
      {
        static constexpr uint32_t msr_id = 0x480;
        using result_type = uint64_t;
      };

      struct vmx_misc
      {
        static constexpr uint32_t msr_id = 0x485;
        using result_type = uint64_t;
      };

      struct vmx_cr0_fixed0
      {
        static constexpr uint32_t msr_id = 0x486;
        using result_type = uint64_t;
      };

      struct vmx_cr0_fixed1
      {
        static constexpr uint32_t msr_id = 0x487;
        using result_type = uint64_t;
      };

      struct vmx_cr4_fixed0
      {
        static constexpr uint32_t msr_id = 0x488;
        using result_type = uint64_t;
      };

      struct vmx_cr4_fixed1
      {
        static constexpr uint32_t msr_id = 0x489;
        using result_type = uint64_t;
      };

      struct vmx_vmcs_enum
      {
        static constexpr uint32_t msr_id = 0x48a;
        using result_type = uint64_t;
      };

      struct vmx_entry_ctls_t
      {
        static constexpr uint32_t msr_id = 0x00000484;
        using result_type = vmx_entry_ctls_t;

        union
        {
          uint64_t all;

          struct
          {
            uint64_t reserved_1 : 2;
            uint64_t load_debug_controls : 1;
            uint64_t reserved_2 : 6;
            uint64_t ia32e_mode_guest : 1;
            uint64_t entry_to_smm : 1;
            uint64_t deactivate_dual_monitor_treatment : 1;
            uint64_t reserved_3 : 1;
            uint64_t load_ia32_perf_global_ctrl : 1;
            uint64_t load_ia32_pat : 1;
            uint64_t load_ia32_efer : 1;
            uint64_t load_ia32_bndcfgs : 1;
            uint64_t conceal_vmx_from_pt : 1;
          }flags;
        };
      };

      struct vmx_procbased_ctls2_t
      {
        static constexpr uint32_t msr_id = 0x0000048B;
        using result_type = vmx_procbased_ctls2_t;

        union
        {
          uint64_t all;

          struct
          {
            uint64_t virtualize_apic_accesses : 1;
            uint64_t enable_ept : 1;
            uint64_t descriptor_table_exiting : 1;
            uint64_t enable_rdtscp : 1;
            uint64_t virtualize_x2apic_mode : 1;
            uint64_t enable_vpid : 1;
            uint64_t wbinvd_exiting : 1;
            uint64_t unrestricted_guest : 1;
            uint64_t apic_register_virtualization : 1;
            uint64_t virtual_interrupt_delivery : 1;
            uint64_t pause_loop_exiting : 1;
            uint64_t rdrand_exiting : 1;
            uint64_t enable_invpcid : 1;
            uint64_t enable_vm_functions : 1;
            uint64_t vmcs_shadowing : 1;
            uint64_t enable_encls_exiting : 1;
            uint64_t rdseed_exiting : 1;
            uint64_t enable_pml : 1;
            uint64_t ept_violation_ve : 1;
            uint64_t conceal_vmx_from_pt : 1;
            uint64_t enable_xsaves : 1;
            uint64_t reserved_1 : 1;
            uint64_t mode_based_execute_control_for_ept : 1;
            uint64_t reserved_2 : 2;
            uint64_t use_tsc_scaling : 1;
          }flags;
        };
      };

      union mtrr_physbase_register_t
      {
        static constexpr uint32_t msr_id = 0x00000200;
        using result_type = mtrr_physbase_register_t;

        uint64_t all;

        struct
        {
          /**
          * [Bits 7:0] Specifies the memory type for the range.
          */
          uint64_t type : 8;
          uint64_t reserved_1 : 4;

          /**
          * [Bits 47:12] Specifies the base address of the address range. This 24-bit value, in the case where MAXPHYADDR is 36
          * bits, is extended by 12 bits at the low end to form the base address (this automatically aligns the address on a 4-KByte
          * boundary).
          */
          uint64_t page_frame_number : 36;
          uint64_t reserved_2 : 16;
        }flags;
      };

      union mtrr_physmask_register_t
      {
        static constexpr uint32_t msr_id = 0x00000201;
        using result_type = mtrr_physmask_register_t;

        uint64_t all;

        struct
        {
          /**
          * [Bits 7:0] Specifies the memory type for the range.
          */
          uint64_t type : 8;
          uint64_t reserved_1 : 3;

          /**
          * [Bit 11] Enables the register pair when set; disables register pair when clear.
          */
          uint64_t valid : 1;

          /**
          * [Bits 47:12] Specifies a mask (24 bits if the maximum physical address size is 36 bits, 28 bits if the maximum physical
          * address size is 40 bits). The mask determines the range of the region being mapped, according to the following
          * relationships:
          * - Address_Within_Range AND PhysMask = PhysBase AND PhysMask
          * - This value is extended by 12 bits at the low end to form the mask value.
          * - The width of the PhysMask field depends on the maximum physical address size supported by the processor.
          * CPUID.80000008H reports the maximum physical address size supported by the processor. If CPUID.80000008H is not
          * available, software may assume that the processor supports a 36-bit physical address size.
          *
          * @see Vol3A[11.11.3(Example Base and Mask Calculations)]
          */
          uint64_t page_frame_number : 36;
          uint64_t reserved_2 : 16;
        }flags;
      };

      union mttr_capabilities_register_t
      {
        static constexpr uint32_t msr_id = 0x000000FE;
        using result_type = mttr_capabilities_register_t;

        uint64_t all;

        struct
        {
          /**
          * @brief VCNT (variable range registers count) field
          *
          * [Bits 7:0] Indicates the number of variable ranges implemented on the processor.
          */
          uint64_t variable_range_count : 8;

          /**
          * @brief FIX (fixed range registers supported) flag
          *
          * [Bit 8] Fixed range MTRRs (MSR_IA32_MTRR_FIX64K_00000 through MSR_IA32_MTRR_FIX4K_0F8000) are supported when set; no fixed range
          * registers are supported when clear.
          */
          uint64_t fixed_range_supported : 1;
          uint64_t reserved_1 : 1;

          /**
          * @brief WC (write combining) flag
          *
          * [Bit 10] The write-combining (WC) memory type is supported when set; the WC type is not supported when clear.
          */
          uint64_t wc_supported : 1;

          /**
          * @brief SMRR (System-Management Range Register) flag
          *
          * [Bit 11] The system-management range register (SMRR) interface is supported when bit 11 is set; the SMRR interface is
          * not supported when clear.
          */
          uint64_t smrr_supported : 1;
          uint64_t reserved_2 : 52;
        }flags;
      };

      union vmx_ept_vpid_cap_register_t
      {
        static constexpr uint32_t msr_id = 0x48c;
        using result_type = vmx_ept_vpid_cap_register_t;

        uint64_t all;

        struct
        {
          /**
          * [Bit 0] When set to 1, the processor supports execute-only translations by EPT. This support allows software to
          * configure EPT paging-structure entries in which bits 1:0 are clear (indicating that data accesses are not allowed) and
          * bit 2 is set (indicating that instruction fetches are allowed).
          */
          uint64_t execute_only_pages : 1;
          uint64_t reserved_1 : 5;

          /**
          * [Bit 6] Indicates support for a page-walk length of 4.
          */
          uint64_t page_walk_length_4 : 1;
          uint64_t reserved_2 : 1;

          /**
          * [Bit 8] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be
          * uncacheable (UC).
          *
          * @see Vol3C[24.6.11(Extended-Page-Table Pointer (EPTP))]
          */
          uint64_t memory_type_uncacheable : 1;
          uint64_t reserved_3 : 5;

          /**
          * [Bit 14] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be
          * write-back (WB).
          */
          uint64_t memory_type_write_back : 1;
          uint64_t reserved_4 : 1;

          /**
          * [Bit 16] When set to 1, the logical processor allows software to configure a EPT PDE to map a 2-Mbyte page (by setting
          * bit 7 in the EPT PDE).
          */
          uint64_t pde_2mb_pages : 1;

          /**
          * [Bit 17] When set to 1, the logical processor allows software to configure a EPT PDPTE to map a 1-Gbyte page (by setting
          * bit 7 in the EPT PDPTE).
          */
          uint64_t pdpte_1gb_pages : 1;
          uint64_t reserved_5 : 2;

          /**
          * [Bit 20] If bit 20 is read as 1, the INVEPT instruction is supported.
          *
          * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
          * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
          */
          uint64_t invept : 1;

          /**
          * [Bit 21] When set to 1, accessed and dirty flags for EPT are supported.
          *
          * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
          */
          uint64_t ept_accessed_and_dirty_flags : 1;

          /**
          * [Bit 22] When set to 1, the processor reports advanced VM-exit information for EPT violations. This reporting is done
          * only if this bit is read as 1.
          *
          * @see Vol3C[27.2.1(Basic VM-Exit Information)]
          */
          uint64_t advanced_vmexit_ept_violations_information : 1;
          uint64_t reserved_6 : 2;

          /**
          * [Bit 25] When set to 1, the single-context INVEPT type is supported.
          *
          * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
          * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
          */
          uint64_t invept_single_context : 1;

          /**
          * [Bit 26] When set to 1, the all-context INVEPT type is supported.
          *
          * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
          * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
          */
          uint64_t invept_all_contexts : 1;
          uint64_t reserved_7 : 5;

          /**
          * [Bit 32] When set to 1, the INVVPID instruction is supported.
          */
          uint64_t invvpid : 1;
          uint64_t reserved_8 : 7;

          /**
          * [Bit 40] When set to 1, the individual-address INVVPID type is supported.
          */
          uint64_t invvpid_individual_address : 1;

          /**
          * [Bit 41] When set to 1, the single-context INVVPID type is supported.
          */
          uint64_t invvpid_single_context : 1;

          /**
          * [Bit 42] When set to 1, the all-context INVVPID type is supported.
          */
          uint64_t invvpid_all_contexts : 1;

          /**
          * [Bit 43] When set to 1, the single-context-retaining-globals INVVPID type is supported.
          */
          uint64_t invvpid_single_context_retain_globals : 1;
          uint64_t reserved_9 : 20;
        }flags;
      };

      struct vmx_true_pinbased_ctls
      {
        static constexpr uint32_t msr_id = 0x48d;
        using result_type = uint64_t;
      };

      struct vmx_true_exit_ctls
      {
        static constexpr uint32_t msr_id = 0x48f;
        using result_type = uint64_t;
      };

      struct vmx_true_entry_ctls
      {
        static constexpr uint32_t msr_id = 0x490;
        using result_type = uint64_t;
      };

      struct vmx_vmfunc
      {
        static constexpr uint32_t msr_id = 0x491;
        using result_type = uint64_t;
      };

      struct sysenter_cs
      {
        static constexpr uint32_t msr_id = 0x174;
        using result_type = uint64_t;
      };

      struct sysenter_esp
      {
        static constexpr uint32_t msr_id = 0x175;
        using result_type = uint64_t;
      };

      struct sysenter_eip
      {
        static constexpr uint32_t msr_id = 0x176;
        using result_type = uint64_t;
      };

      struct debugctl
      {
        static constexpr uint32_t msr_id = 0x1d9;
        using result_type = uint64_t;
      };

      struct shadow_gs_base
      {
        static constexpr uint32_t msr_id = 0xc0000102;
        using result_type = uint64_t;
      };

      inline constexpr uint32_t low_msr_high_range = 0x00001FFF;
      inline constexpr uint32_t high_msr_low_range = 0xC0000000;
      inline constexpr uint32_t high_msr_high_range = 0xC0001FFF;

      inline constexpr uint32_t low_msr_write_bitmap_offset = 2048;
      inline constexpr uint32_t high_msr_read_bitmap_offset = 1024;
      inline constexpr uint32_t high_msr_write_bitmap_offset = 3072;

      struct apic_base_t
      {
        static constexpr uint32_t msr_id = 0x0000001b;
        using result_type = apic_base_t;

        union
        {
          uint64_t flags;

          struct
          {
            uint64_t reserved_1 : 8;
            uint64_t bsp_flag : 1;
            uint64_t reserved_2 : 1;
            uint64_t enable_x2apic_mode : 1;
            uint64_t apic_global_enable : 1;
            uint64_t page_frame_number : 36;
          };
        };
      };

      struct debugctl_t
      {
        static constexpr uint32_t msr_id = 0x000001d9;
        using result_type = debugctl_t;

        union
        {
          uint64_t all;

          struct
          {
            uint64_t lbr : 1;
            uint64_t btf : 1;
            uint64_t reserved_1 : 4;
            uint64_t tr : 1;
            uint64_t bts : 1;
            uint64_t btint : 1;
            uint64_t bts_off_os : 1;
            uint64_t bts_off_usr : 1;
            uint64_t freeze_lbrs_on_pmi : 1;
            uint64_t freeze_perfmon_on_pmi : 1;
            uint64_t enable_uncore_pmi : 1;
            uint64_t freeze_while_smm : 1;
            uint64_t rtm_debug : 1;
          }fields;
        };
      };

      struct efer_t
      {
        static constexpr uint32_t msr_id = 0xc0000080;
        using result_type = efer_t;

        union
        {
          uint64_t all;

          struct
          {
            uint64_t syscall_enable : 1;
            uint64_t reserved1 : 7;
            uint64_t ia32e_mode_enable : 1;
            uint64_t reserved2 : 1;
            uint64_t ia32e_mode_active : 1;
            uint64_t execute_disable_bit_enable : 1;
            uint64_t reserved3 : 52;
          }fields;
        };
      };

      struct feature_control_msr_t
      {
        static constexpr uint32_t msr_id = 0x03A;
        using result_type = feature_control_msr_t;

        union
        {
          uint64_t all;

          struct
          {
            uint64_t lock : 1;
            uint64_t enable_smx : 1;
            uint64_t enable_vmxon : 1;
            uint64_t reserved_2 : 5;
            uint64_t enable_local_senter : 7;
            uint64_t enable_global_senter : 1;
            uint64_t reserved_3a : 16;
            uint64_t reserved_3b : 32;
          } fields;
        };
      };

      struct vmx_basic_msr_t
      {
        inline static constexpr uint32_t msr_id = 0x480;
        using result_type = vmx_basic_msr_t;

        union
        {
          uint64_t all;

          struct
          {
            uint32_t revision_identifier : 31;
            uint32_t reserved_1 : 1;
            uint32_t region_size : 12;
            uint32_t region_clear : 1;
            uint32_t reserved_2 : 3;
            uint32_t supported_ia64 : 1;
            uint32_t supported_dual_moniter : 1;
            uint32_t memory_type : 4;
            uint32_t vmexit_report : 1;
            uint32_t vmx_capability_hint : 1;
            uint32_t reserved_3 : 8;
          } fields;
        };
      };

      struct vmx_pinbased_ctls_t
      {
        static constexpr uint32_t msr_id = 0x00000481;
        using result_type = vmx_pinbased_ctls_t;

        union
        {
          uint64_t all;

          struct
          {
            uint64_t external_interrupt_exiting : 1;
            uint64_t reserved_1 : 2;
            uint64_t nmi_exiting : 1;
            uint64_t reserved_2 : 1;
            uint64_t virtual_nmis : 1;
            uint64_t activate_vmx_preemption_timer : 1;
            uint64_t process_posted_interrupts : 1;
          }flags;
        };
      };

      struct vmx_procbased_ctls_t
      {
        static constexpr uint32_t msr_id = 0x00000482;
        using result_type = vmx_procbased_ctls_t;
        union
        {
          uint64_t all;

          struct
          {
            uint64_t reserved_1 : 2;
            uint64_t interrupt_window_exiting : 1;
            uint64_t use_tsc_offsetting : 1;
            uint64_t reserved_2 : 3;
            uint64_t hlt_exiting : 1;
            uint64_t reserved_3 : 1;
            uint64_t invlpg_exiting : 1;
            uint64_t mwait_exiting : 1;
            uint64_t rdpmc_exiting : 1;
            uint64_t rdtsc_exiting : 1;
            uint64_t reserved_4 : 2;
            uint64_t cr3_load_exiting : 1;
            uint64_t cr3_store_exiting : 1;
            uint64_t reserved_5 : 2;
            uint64_t cr8_load_exiting : 1;
            uint64_t cr8_store_exiting : 1;
            uint64_t use_tpr_shadow : 1;
            uint64_t nmi_window_exiting : 1;
            uint64_t mov_dr_exiting : 1;
            uint64_t unconditional_io_exiting : 1;
            uint64_t use_io_bitmaps : 1;
            uint64_t reserved_6 : 1;
            uint64_t monitor_trap_flag : 1;
            uint64_t use_msr_bitmaps : 1;
            uint64_t monitor_exiting : 1;
            uint64_t pause_exiting : 1;
            uint64_t activate_secondary_controls : 1;
          }flags;
        };
      };

      struct vmx_exit_ctls_t
      {
        static constexpr uint32_t msr_id = 0x00000483;
        using result_type = vmx_exit_ctls_t;

        union
        {
          uint64_t all;

          struct
          {
            uint64_t reserved_1 : 2;
            uint64_t save_debug_controls : 1;
            uint64_t reserved_2 : 6;
            uint64_t ia32e_mode_host : 1;
            uint64_t reserved_3 : 2;
            uint64_t load_perf_global_ctrl : 1;
            uint64_t reserved_4 : 2;
            uint64_t acknowledge_interrupt_on_exit : 1;
            uint64_t reserved_5 : 2;
            uint64_t save_pat : 1;
            uint64_t load_pat : 1;
            uint64_t save_efer : 1;
            uint64_t load_efer : 1;
            uint64_t save_vmx_preemption_timer_value : 1;
            uint64_t clear_bndcfgs : 1;
            uint64_t conceal_vmx_from_pt : 1;
          }flags;
        };
      };

      union def_type_register_t
      {
        static constexpr uint32_t msr_id = 0x000002FF;
        using result_type = def_type_register_t;

        uint64_t all;

        struct
        {
          uint64_t default_memory_type : 3;
          uint64_t reserved_1 : 7;
          uint64_t fixed_range_mtrr_enable : 1;
          uint64_t mtrr_enable : 1;
          uint64_t reserved_2 : 52;
        }flags;
      };

      struct vmx_true_procbased_ctls
      {
        static constexpr uint32_t msr_id = 0x48e;
        using result_type = uint64_t;
      };

      struct star
      {
        static constexpr uint32_t msr_id = 0xc0000081;
        using result_type = uint64_t;
      };

      struct lstar
      {
        static constexpr uint32_t msr_id = 0xc0000082;
        using result_type = uint64_t;
      };

      struct cstar
      {
        static constexpr uint32_t msr_id = 0xc0000083;
        using result_type = uint64_t;
      };

      struct fmask
      {
        static constexpr uint32_t msr_id = 0xc0000084;
        using result_type = x86::rflags_t;
      };

      struct fs_base
      {
        static constexpr uint32_t msr_id = 0xc0000100;
        using result_type = uint64_t;
      };

      struct gs_base
      {
        static constexpr uint32_t msr_id = 0xc0000101;
        using result_type = uint64_t;
      };

      union register_content
      {
        struct
        {
          uint32_t low;
          uint32_t high;
        };

        uint64_t all;
      };
    }
  }
}
