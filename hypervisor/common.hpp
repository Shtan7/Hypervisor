#pragma once
#include <stdint.h>
#include <ntddk.h>
#include <type_traits>
#include <intrin.h>
#include "x86-64.hpp"

namespace hh
{
  namespace common
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
    class spinlock_guard
    {
    private:
      static constexpr uint32_t max_wait_ = 65536;
      volatile long* lock_;

    private:
      bool try_lock() noexcept;
      void lock_spinlock() noexcept;
      void unlock() noexcept;

    public:
      spinlock_guard(volatile long* lock) noexcept;
      ~spinlock_guard() noexcept;
    };

    // RAII irql guard.
    class irql_guard
    {
    private:
      KIRQL old_irql_;

    public:
      irql_guard(KIRQL new_irql) noexcept;
      ~irql_guard() noexcept;
    };

    // RAII cr3 guard.
    class directory_base_guard
    {
    private:
      x86::cr3_t old_cr3_;

    public:
      directory_base_guard(x86::cr3_t new_cr3) noexcept;
      ~directory_base_guard() noexcept;
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
}
