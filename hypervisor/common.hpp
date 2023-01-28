#pragma once
#include <cstdint>
#include <ntddk.h>
#include <type_traits>
#include <intrin.h>
#include "delete_constructors.hpp"
#include "x86-64.hpp"

namespace hh::common
{
  enum segment_registers
  {
    es = 0,
    cs,
    ss,
    ds,
    fs,
    gs,
    ldtr,
    tr
  };

  // CPUID features
  inline constexpr uint32_t cpuid_processor_and_processor_feature_identifiers = 0x00000001;

  // Page Align
  inline constexpr uint32_t alignment_page_size = 0x1000;

  // System and User ring definitions
  inline constexpr uint32_t dpl_user = 3;
  inline constexpr uint32_t dpl_system = 0;
  inline constexpr uint32_t rpl_mask = 3;
  inline constexpr uint32_t pool_tag = 'cimf';
  inline constexpr uint32_t max_trampoline_size = 120;

  template <typename T>
  union u64_t
  {
    static_assert(sizeof(T) <= sizeof(uint64_t));
    static_assert(std::is_trivial_v<T>);

    uint64_t as_uint64_t;
    T        as_value;
  };

  union rflags
  {
    struct
    {
      unsigned reserved_1 : 10;
      unsigned ID : 1;		// Identification flag
      unsigned VIP : 1;		// Virtual interrupt pending
      unsigned VIF : 1;		// Virtual interrupt flag
      unsigned AC : 1;		// Alignment check
      unsigned VM : 1;		// Virtual 8086 mode
      unsigned RF : 1;		// Resume flag
      unsigned reserved_2 : 1;
      unsigned NT : 1;		// Nested task flag
      unsigned IOPL : 2;		// I/O privilege level
      unsigned OF : 1;
      unsigned DF : 1;
      unsigned IF : 1;		// Interrupt flag
      unsigned TF : 1;		// Task flag
      unsigned SF : 1;		// Sign flag
      unsigned ZF : 1;		// Zero flag
      unsigned reserved_3 : 1;
      unsigned AF : 1;		// Borrow flag
      unsigned reserved_4 : 1;
      unsigned PF : 1;		// Parity flag
      unsigned reserved_5 : 1;
      unsigned CF : 1;		// Carry flag [Bit 0]
      unsigned reserved_6 : 32;
    };

    uint64_t content;
  };

  union segment_attributes
  {
    uint16_t all;

    struct
    {
      uint16_t TYPE : 4;              /* 0;  Bit 40-43 */
      uint16_t S : 1;                 /* 4;  Bit 44 */
      uint16_t DPL : 2;               /* 5;  Bit 45-46 */
      uint16_t P : 1;                 /* 7;  Bit 47 */

      uint16_t AVL : 1;               /* 8;  Bit 52 */
      uint16_t L : 1;                 /* 9;  Bit 53 */
      uint16_t DB : 1;                /* 10; Bit 54 */
      uint16_t G : 1;                 /* 11; Bit 55 */
      uint16_t GAP : 4;

    } fields;
  };

  struct segment_selector
  {
    uint16_t sel;
    segment_attributes attributes;
    uint32_t limit;
    uint64_t base;
  };

  struct segment_descriptor
  {
    uint16_t limit_0;
    uint16_t base_0;
    uint8_t  base_1;
    uint8_t  attr_0;
    uint8_t  limit_1_attr_1;
    uint8_t  base_2;
  };

  struct cpuid_t
  {
    int eax;
    int ebx;
    int ecx;
    int edx;
  };

  struct nt_kprocess
  {
    DISPATCHER_HEADER header;
    LIST_ENTRY profile_list_head;
    uint64_t directory_table_base;
    uint8_t data[1];
  };

  struct fxsave_area
  {
    uint16_t control_word;
    uint16_t status_word;
    uint16_t tag_word;
    uint16_t last_instruction_opcode;

    union
    {
      struct
      {
        uint64_t rip;
        uint64_t rdp;
      };

      struct
      {
        uint32_t ip_offset;
        uint32_t ip_selector;
        uint32_t operand_pointer_offset;
        uint32_t operand_pointer_selector;
      };
    };

    uint32_t mxcsr;
    uint32_t mxcsr_mask;

    __m128   st_register[8];    // st0-st7 (mm0-mm7), only 80 bits per register
    // (upper 48 bits of each register are reserved)

    __m128   xmm_register[16];  // xmm0-xmm15
    uint8_t  reserved_1[48];

    union
    {
      uint8_t reserved_2[48];
      uint8_t software_available[48];
    };
  };

  struct cpuid_eax_01
  {
    union
    {
      struct
      {
        uint32_t cpu_info[4];
      };

      struct
      {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
      };

      struct
      {
        union
        {
          uint32_t flags;

          struct
          {
            uint32_t stepping_id : 4;
            uint32_t model : 4;
            uint32_t family_id : 4;
            uint32_t processor_type : 2;
            uint32_t reserved1 : 2;
            uint32_t extended_model_id : 4;
            uint32_t extended_family_id : 8;
            uint32_t reserved2 : 4;
          };
        } version_information;

        union
        {
          uint32_t flags;

          struct
          {
            uint32_t brand_index : 8;
            uint32_t clflush_line_size : 8;
            uint32_t max_addressable_ids : 8;
            uint32_t initial_apic_id : 8;
          };
        } additional_information;

        union
        {
          uint32_t flags;

          struct
          {
            uint32_t streaming_simd_extensions_3 : 1;
            uint32_t pclmulqdq_instruction : 1;
            uint32_t ds_area_64bit_layout : 1;
            uint32_t monitor_mwait_instruction : 1;
            uint32_t cpl_qualified_debug_store : 1;
            uint32_t virtual_machine_extensions : 1;
            uint32_t safer_mode_extensions : 1;
            uint32_t enhanced_intel_speedstep_technology : 1;
            uint32_t thermal_monitor_2 : 1;
            uint32_t supplemental_streaming_simd_extensions_3 : 1;
            uint32_t l1_context_id : 1;
            uint32_t silicon_debug : 1;
            uint32_t fma_extensions : 1;
            uint32_t cmpxchg16b_instruction : 1;
            uint32_t xtpr_update_control : 1;
            uint32_t perfmon_and_debug_capability : 1;
            uint32_t reserved1 : 1;
            uint32_t process_context_identifiers : 1;
            uint32_t direct_cache_access : 1;
            uint32_t sse41_support : 1;
            uint32_t sse42_support : 1;
            uint32_t x2apic_support : 1;
            uint32_t movbe_instruction : 1;
            uint32_t popcnt_instruction : 1;
            uint32_t tsc_deadline : 1;
            uint32_t aesni_instruction_extensions : 1;
            uint32_t xsave_xrstor_instruction : 1;
            uint32_t osx_save : 1;
            uint32_t avx_support : 1;
            uint32_t half_precision_conversion_instructions : 1;
            uint32_t rdrand_instruction : 1;
            uint32_t hypervisor_present : 1;
          };
        } feature_information_ecx;

        union
        {
          uint32_t flags;

          struct
          {
            uint32_t floating_point_unit_on_chip : 1;
            uint32_t virtual_8086_mode_enhancements : 1;
            uint32_t debugging_extensions : 1;
            uint32_t page_size_extension : 1;
            uint32_t timestamp_counter : 1;
            uint32_t rdmsr_wrmsr_instructions : 1;
            uint32_t physical_address_extension : 1;
            uint32_t machine_check_exception : 1;
            uint32_t cmpxchg8b : 1;
            uint32_t apic_on_chip : 1;
            uint32_t reserved1 : 1;
            uint32_t sysenter_sysexit_instructions : 1;
            uint32_t memory_type_range_registers : 1;
            uint32_t page_global_bit : 1;
            uint32_t machine_check_architecture : 1;
            uint32_t conditional_move_instructions : 1;
            uint32_t page_attribute_table : 1;
            uint32_t page_size_extension_36bit : 1;
            uint32_t processor_serial_number : 1;
            uint32_t clflush : 1;
            uint32_t reserved2 : 1;
            uint32_t debug_store : 1;
            uint32_t thermal_control_msrs_for_acpi : 1;
            uint32_t mmx_support : 1;
            uint32_t fxsave_fxrstor_instructions : 1;
            uint32_t sse_support : 1;
            uint32_t sse2_support : 1;
            uint32_t self_snoop : 1;
            uint32_t hyper_threading_technology : 1;
            uint32_t thermal_monitor : 1;
            uint32_t reserved3 : 1;
            uint32_t pending_break_enable : 1;
          };
        } feature_information_edx;
      };
    };
  };

  struct guest_regs
  {
    fxsave_area* fx_area;
    uint64_t rax;                  // 0x00         
    uint64_t rcx;
    uint64_t rdx;                  // 0x10
    uint64_t rbx;
    uint64_t rsp;                  // 0x20         // rsp is not stored here
    uint64_t rbp;
    uint64_t rsi;                  // 0x30
    uint64_t rdi;
    uint64_t r8;                   // 0x40
    uint64_t r9;
    uint64_t r10;                  // 0x50
    uint64_t r11;
    uint64_t r12;                  // 0x60
    uint64_t r13;
    uint64_t r14;                  // 0x70
    uint64_t r15;
  };

  // RAII spinlock.
  class spinlock_guard : non_copyable
  {
  private:
    static constexpr uint32_t max_wait_ = 65536;
    volatile long* lock_;

  private:
    bool try_lock() noexcept;
    void lock_spinlock() noexcept;
    void unlock() noexcept;

  public:
    spinlock_guard(spinlock_guard&&);
    spinlock_guard& operator=(spinlock_guard&&);
    spinlock_guard(volatile long* lock) noexcept;
    ~spinlock_guard() noexcept;
  };

  // RAII irql guard.
  class irql_guard : non_relocatable
  {
  private:
    KIRQL old_irql_;

  public:
    irql_guard(KIRQL new_irql) noexcept;
    ~irql_guard() noexcept;
  };

  // Set - Unset bit
#define BITS_PER_LONG (sizeof(UINT32) * 8)
#define BITMAP_ENTRY(nr, bmap) ((bmap))[(nr) / BITS_PER_LONG]
#define BITMAP_SHIFT(nr) ((nr) % BITS_PER_LONG)

  // Translate virtual address to physical.
  uint64_t virtual_address_to_physical_address(void* virtual_address) noexcept;
  // Translate physical address to virtual.
  uint64_t physical_address_to_virtual_address(uint64_t physical_address) noexcept;
  // Set chosen bit.
  void set_bit(void* address, uint64_t bit, bool set) noexcept;
  // Get chosen bit.
  uint8_t get_bit(void* address, uint64_t bit) noexcept;
  // Get cr3 of the system process.
  uint64_t find_system_directory_table_base() noexcept;
  double log2(double d) noexcept;
  constexpr uint64_t compile_time_log2(uint64_t x)
  {
    return x == 1 ? 0 : 1 + compile_time_log2(x / 2);
  }
}
