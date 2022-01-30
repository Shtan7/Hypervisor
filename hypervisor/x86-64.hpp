#pragma once
#include <stdint.h>
#include <type_traits>
#include <intrin.h>
#include "asm.hpp"
#include "msr.hpp"
#include "segment.hpp"

namespace hh
{
  namespace x86
  {
    struct rflags_t
    {
      //
      // Reserved bits.
      //
      static constexpr uint64_t reserved_bits = 0xffc38028;

      //
      // Bits that are fixed to 1 ("read_as_1" field).
      //
      static constexpr uint64_t fixed_bits    = 0x00000002;

      union
      {
        uint64_t all;

        struct
        {
          uint64_t carry_flag : 1;
          uint64_t read_as_1 : 1;
          uint64_t parity_flag : 1;
          uint64_t reserved_1 : 1;
          uint64_t auxiliary_carry_flag : 1;
          uint64_t reserved_2 : 1;
          uint64_t zero_flag : 1;
          uint64_t sign_flag : 1;
          uint64_t trap_flag : 1;
          uint64_t interrupt_enable_flag : 1;
          uint64_t direction_flag : 1;
          uint64_t overflow_flag : 1;
          uint64_t io_privilege_level : 2;
          uint64_t nested_task_flag : 1;
          uint64_t reserved_3 : 1;
          uint64_t resume_flag : 1;
          uint64_t virtual_8086_mode_flag : 1;
          uint64_t alignment_check_flag : 1;
          uint64_t virtual_interrupt_flag : 1;
          uint64_t virtual_interrupt_pending_flag : 1;
          uint64_t identification_flag : 1;
        }flags;
      };
    };

    struct dr0_t { uint64_t all; };
    struct dr1_t { uint64_t all; };
    struct dr2_t { uint64_t all; };
    struct dr3_t { uint64_t all; };
    struct dr4_t { uint64_t all; };
    struct dr5_t { uint64_t all; };

    struct dr6_t
    {
      union
      {
        uint64_t all;

        struct
        {
          uint64_t breakpoint_condition : 4;
          uint64_t reserved_1 : 8; // always 1
          uint64_t reserved_2 : 1; // always 0
          uint64_t debug_register_access_detected : 1;
          uint64_t single_instruction : 1;
          uint64_t task_switch : 1;
          uint64_t restricted_transactional_memory : 1;
          uint64_t reserved_3 : 15; // always 1
        }flags;
      };
    };

    struct dr7_t
    {
      union
      {
        uint64_t all;

        struct
        {
          uint64_t local_breakpoint_0 : 1;
          uint64_t global_breakpoint_0 : 1;
          uint64_t local_breakpoint_1 : 1;
          uint64_t global_breakpoint_1 : 1;
          uint64_t local_breakpoint_2 : 1;
          uint64_t global_breakpoint_2 : 1;
          uint64_t local_breakpoint_3 : 1;
          uint64_t global_breakpoint_3 : 1;
          uint64_t local_exact_breakpoint : 1;
          uint64_t global_exact_breakpoint : 1;
          uint64_t reserved_1 : 1; // always 1
          uint64_t restricted_transactional_memory : 1;
          uint64_t reserved_2 : 1; // always 0
          uint64_t general_detect : 1;
          uint64_t reserved_3 : 2; // always 0
          uint64_t read_write_0 : 2;
          uint64_t length_0 : 2;
          uint64_t read_write_1 : 2;
          uint64_t length_1 : 2;
          uint64_t read_write_2 : 2;
          uint64_t length_2 : 2;
          uint64_t read_write_3 : 2;
          uint64_t length_3 : 2;
        }flags;
      };
    };

    struct cr0_t
    {
      union
      {
        uint64_t all;

        struct
        {
          uint64_t protection_enable : 1;
          uint64_t monitor_coprocessor : 1;
          uint64_t emulate_fpu : 1;
          uint64_t task_switched : 1;
          uint64_t extension_type : 1;
          uint64_t numeric_error : 1;
          uint64_t reserved_1 : 10;
          uint64_t write_protect : 1;
          uint64_t reserved_2 : 1;
          uint64_t alignment_mask : 1;
          uint64_t reserved_3 : 10;
          uint64_t not_write_through : 1;
          uint64_t cache_disable : 1;
          uint64_t paging_enable : 1;
        }flags;
      };
    };

    struct cr2_t
    {
      union
      {
        uint64_t all;
        uint64_t linear_address;
      };
    };

    struct cr3_t
    {
      union
      {
        uint64_t all;

        struct
        {
          uint64_t pcid : 12;
          uint64_t page_frame_number : 36;
          uint64_t reserved_1 : 12;
          uint64_t reserved_2 : 3;
          uint64_t pcid_invalidate : 1;
        }flags;
      };
    };

    struct cr4_t
    {
      union
      {
        uint64_t all;

        struct
        {
          uint64_t virtual_mode_extensions : 1;
          uint64_t protected_mode_virtual_interrupts : 1;
          uint64_t timestamp_disable : 1;
          uint64_t debugging_extensions : 1;
          uint64_t page_size_extensions : 1;
          uint64_t physical_address_extension : 1;
          uint64_t machine_check_enable : 1;
          uint64_t page_global_enable : 1;
          uint64_t performance_monitoring_counter_enable : 1;
          uint64_t os_fxsave_fxrstor_support : 1;
          uint64_t os_xmm_exception_support : 1;
          uint64_t usermode_instruction_prevention : 1;
          uint64_t reserved_1 : 1;
          uint64_t vmx_enable : 1;
          uint64_t smx_enable : 1;
          uint64_t reserved_2 : 1;
          uint64_t fsgsbase_enable : 1;
          uint64_t pcid_enable : 1;
          uint64_t os_xsave : 1;
          uint64_t reserved_3 : 1;
          uint64_t smep_enable : 1;
          uint64_t smap_enable : 1;
          uint64_t protection_key_enable : 1;
        }flags;
      };
    };

    template <typename T> T    read()         noexcept { __int2c(); }
    template <typename T> void write(T value) noexcept { __int2c(); }

    template <> inline cr0_t    read() noexcept { return cr0_t    { __readcr0() };    }
    template <> inline cr2_t    read() noexcept { return cr2_t    { __readcr2() };    }
    template <> inline cr3_t    read() noexcept { return cr3_t    { __readcr3() };    }
    template <> inline cr4_t    read() noexcept { return cr4_t    { __readcr4() };    }

    template <> inline dr0_t    read() noexcept { return dr0_t    { __read_dr(0) };    }
    template <> inline dr1_t    read() noexcept { return dr1_t    { __read_dr(1) };    }
    template <> inline dr2_t    read() noexcept { return dr2_t    { __read_dr(2) };    }
    template <> inline dr3_t    read() noexcept { return dr3_t    { __read_dr(3) };    }
    template <> inline dr4_t    read() noexcept { return dr4_t    { __read_dr(4) };    }
    template <> inline dr5_t    read() noexcept { return dr5_t    { __read_dr(5) };    }
    template <> inline dr6_t    read() noexcept { return dr6_t    { __read_dr(6) };    }
    template <> inline dr7_t    read() noexcept { return dr7_t    { __read_dr(7) };    }

    template <> inline rflags_t read() noexcept { return rflags_t { __read_rflags() }; }

    template <> inline cs_t     read() noexcept { return cs_t     { __read_cs() };     }
    template <> inline ds_t     read() noexcept { return ds_t     { __read_ds() };     }
    template <> inline es_t     read() noexcept { return es_t     { __read_es() };     }
    template <> inline fs_t     read() noexcept { return fs_t     { __read_fs() };     }
    template <> inline ss_t     read() noexcept { return ss_t     { __read_ss() };     }
    template <> inline gs_t     read() noexcept { return gs_t     { __read_gs() };     }
    template <> inline tr_t     read() noexcept { return tr_t     { __read_tr() };     }
    template <> inline ldtr_t   read() noexcept { return ldtr_t   { __read_ldtr() };   }

    template <> inline gdtr_t   read() noexcept { gdtr_t result; __read_gdt(&result); return result; }
    template <> inline idtr_t   read() noexcept { idtr_t result; __read_idt(&result); return result; }


    template <> inline void write(cr0_t value)    noexcept { __writecr0(value.all); }
    template <> inline void write(cr2_t value)    noexcept { __writecr2(value.all); }
    template <> inline void write(cr3_t value)    noexcept { __writecr3(value.all); }
    template <> inline void write(cr4_t value)    noexcept { __writecr4(value.all); }

    template <> inline void write(dr0_t value)    noexcept { __write_dr(0, value.all); }
    template <> inline void write(dr1_t value)    noexcept { __write_dr(1, value.all); }
    template <> inline void write(dr2_t value)    noexcept { __write_dr(2, value.all); }
    template <> inline void write(dr3_t value)    noexcept { __write_dr(3, value.all); }
    template <> inline void write(dr4_t value)    noexcept { __write_dr(4, value.all); }
    template <> inline void write(dr5_t value)    noexcept { __write_dr(5, value.all); }
    template <> inline void write(dr6_t value)    noexcept { __write_dr(6, value.all); }
    template <> inline void write(dr7_t value)    noexcept { __write_dr(7, value.all); }

    template <> inline void write(rflags_t value) noexcept { __write_rflags(value.all); }

    template <> inline void write(cs_t value)     noexcept { __write_cs(value.all); }
    template <> inline void write(ds_t value)     noexcept { __write_ds(value.all); }
    template <> inline void write(es_t value)     noexcept { __write_es(value.all); }
    template <> inline void write(fs_t value)     noexcept { __write_fs(value.all); }
    template <> inline void write(gs_t value)     noexcept { __write_gs(value.all); }
    template <> inline void write(ss_t value)     noexcept { __write_ss(value.all); }
    template <> inline void write(tr_t value)     noexcept { __write_tr(value.all); }
    template <> inline void write(ldtr_t value)   noexcept { __write_ldtr(value.all); }

    template <> inline void write(gdtr_t value)   noexcept { __write_gdt(&value); }
    template <> inline void write(idtr_t value)   noexcept { __write_idt(&value); }

    namespace msr
    {
      template<class T> inline auto read(uint64_t offset) noexcept { return (typename T::result_type)__readmsr(T::msr_id + offset); }
      template<class T> inline auto read() noexcept { return (typename T::result_type)__readmsr(T::msr_id); }
      template<class T> inline void write(uint64_t value) noexcept { __writemsr(T::msr_id, value); }
      template<class T> inline void write(T reg) noexcept { __writemsr(reg.msr_id, reg.all); }
    }
  }
}
