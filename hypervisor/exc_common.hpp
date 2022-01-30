#pragma once
#include "type_info.hpp"
#include <stdint.h>
#include <type_traits>
#include <ntimage.h>

#define BREAK_IF_FALSE(cond) \
  if (!(cond))               \
    break

namespace exc
{
  extern "C" uint8_t __ImageBase;

  template <typename Ty, typename IntegralTy>
  Ty convert_narrow(IntegralTy value) noexcept
  {
    return static_cast<Ty>(value);
  }

  template <typename Ty>
  struct relative_virtual_address
  {
    uint32_t offset{ 0 };

    constexpr relative_virtual_address() = default;

    constexpr relative_virtual_address(uint32_t offset) noexcept
      : offset{offset} {}

    relative_virtual_address(Ty* ptr, const void* base) noexcept
      : offset{calculate_offset(ptr, base)} {}

    constexpr explicit operator bool() const noexcept
    {
      return static_cast<bool>(offset);
    }

    constexpr uint32_t value() const { return offset; }

    constexpr relative_virtual_address& operator+=(uint32_t rhs) noexcept
    {
      offset += rhs;
      return *this;
    }

    template <typename OtherTy, std::enable_if<std::is_convertible_v<OtherTy*, Ty*>, int> = 0>
    constexpr operator relative_virtual_address<OtherTy>() const noexcept
    {
      return relative_virtual_address<OtherTy>{ offset };
    }

    constexpr friend Ty* operator+(const void* base, relative_virtual_address<Ty> rva) noexcept
    {
      return reinterpret_cast<Ty*>(reinterpret_cast<uintptr_t>(base) + rva.value());
    }

    constexpr friend const uint8_t* operator-(Ty* ptr, relative_virtual_address<Ty> rva) noexcept
    {
      return reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(ptr) - rva.value());
    }

    constexpr friend relative_virtual_address operator+(relative_virtual_address lhs, uint32_t rhs) noexcept
    {
      return relative_virtual_address{lhs.offset} += rhs;
    }

    constexpr friend bool operator==(const relative_virtual_address& lhs, const relative_virtual_address& rhs) noexcept
    {
      return lhs.offset == rhs.offset;
    }

    constexpr friend bool operator!=(relative_virtual_address const& lhs, relative_virtual_address const& rhs) noexcept
    {
      return !(lhs == rhs);
    }

    constexpr friend bool operator<(relative_virtual_address const& lhs, relative_virtual_address const& rhs) noexcept
    {
      return lhs.offset < rhs.offset;
    }

    constexpr friend bool operator<=(relative_virtual_address const& lhs, relative_virtual_address const& rhs) noexcept
    {
      return !(rhs < lhs);
    }

    constexpr friend bool operator>(relative_virtual_address const& lhs, relative_virtual_address const& rhs) noexcept
    {
      return rhs < lhs;
    }

    constexpr friend bool operator>=(relative_virtual_address const& lhs, relative_virtual_address const& rhs) noexcept
    {
      return !(lhs < rhs);
    }

    static uint32_t calculate_offset(Ty* ptr, const void* base) noexcept
    {
      return convert_narrow<uint32_t>(reinterpret_cast<uintptr_t>(ptr) - reinterpret_cast<uintptr_t>(base));
    }
  };

  union throw_flags
  {
    struct
    {
      uint32_t is_const : 1;
      uint32_t is_volatile : 1;
      uint32_t is_unaligned : 1;
      uint32_t is_pure : 1;
      uint32_t is_win_rt : 1;
    };

    uint32_t all;
  };

  class member_ptr
  {
  private:
    uint32_t vbase_offset_;
    uint32_t vbtable_ptr_offset_;
    uint32_t member_offset_;

  public:
    member_ptr(uint32_t vbase_offset, uint32_t vbtable_ptr_offset, uint32_t member_offset) noexcept;
    uintptr_t apply(uintptr_t obj) const noexcept;
  };

  union catchable_property
  {
    struct
    {
      uint32_t is_simple_type : 1;
      uint32_t by_reference_only : 1;
      uint32_t has_virtual_base : 1;
      uint32_t is_win_rt_handle : 1;
      uint32_t is_bad_alloc : 1;
    };

    uint32_t all;
  };

  struct catchable_type
  {
    // 0x01: simple type (can be copied by memmove), 0x02: can be caught by reference only, 0x04: has virtual bases
    catchable_property properties;
    relative_virtual_address<type_info const> desc;
    // how to cast the thrown object to this type
    member_ptr offset;
    // object size
    uint32_t size;
    // copy constructor address
    relative_virtual_address<uint8_t const> copy_fn;
  };

  struct catchable_type_list
  {
    uint32_t count;
    relative_virtual_address<const catchable_type> types[1];
  };

  struct throw_info
  {
    throw_flags attributes;
    // exception object destructor
    relative_virtual_address<void __fastcall(void*)> destroy_exc_obj;
    // forward compatibility handler
    relative_virtual_address<int(...)> compat_fn;
    // list of types that can catch this exception.
    // i.e. the actual type and all its ancestors.
    relative_virtual_address<const catchable_type_list> catchables;
  };

  __declspec(align(16)) struct xmm_register { unsigned char data[16]; };

  // Marked offsets are used by the nt!__C_specific_handler
  struct frame_walk_context
  {
    xmm_register xmm6;
    xmm_register xmm7;
    xmm_register xmm8;
    xmm_register xmm9;
    xmm_register xmm10;
    xmm_register xmm11;
    xmm_register xmm12;
    xmm_register xmm13;
    xmm_register xmm14;

    uint64_t padding1;            // 16-uint8_t aligned
    /*0x98*/ uint64_t dummy_rsp;  // 8-uint8_t aligned

    xmm_register xmm15;           // 16-uint8_t aligned

    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    uint64_t padding2;               // 16-uint8_t aligned
    /*0xf8*/ const uint8_t* dummy_rip;  // 8-uint8_t aligned

    uint64_t& gp(uint8_t idx) noexcept;
  };

  struct machine_frame
  {
    const uint8_t* rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
  };

  struct catch_info
  {
    const uint8_t* continuation_address[2];
    uint8_t* primary_frame_ptr;
    void* exception_object_or_link;
    const throw_info* throw_info_if_owner;
    uint64_t unwind_context;

    [[nodiscard]] void* get_exception_object() const noexcept;
    [[nodiscard]] const throw_info* get_throw_info() const noexcept;
  };

  struct throw_frame
  {
    uint64_t red_zone[4];
    frame_walk_context ctx;
    machine_frame mach;
    catch_info catch_info;
  };

  enum class bug_check_reason
  {
    corrupted_machine_state,
    corrupted_pe_header,
    no_matching_exception_handler,
    unwinding_non_cxx_frame,
    corrupted_eh_unwind_data,
    corrupted_exception_handler
  };

  struct bug_check_context
  {
    bug_check_reason reason;
    int64_t arg_1{ 0 }, arg_2{ 0 }, arg_3{ 0 }, arg_4{ 0 };
  };

  enum class unwind_code : uint8_t
  {
    push_non_volatile_reg = 0,      // 1
    alloc_large = 1,                // 2-3
    alloc_small = 2,                // 1
    set_frame_pointer = 3,          // 1
    save_non_volatile_reg = 4,      // 2
    save_far_non_volatile_reg = 5,  // 3
    epilog = 6,                     // 2
    reserved_07 = 7,                // 3 _07
    same_xmm_128 = 8,               // 2
    save_far_xmm_128 = 9,           // 3
    push_machine_frame = 10,        // 1
  };

  struct unwind_entry
  {
    uint8_t prolog_offset;
    unwind_code code : 4;
    uint8_t info : 4;
  };

  struct unwind_info
  {
    // unwinding info version
    uint8_t version : 3;
    uint8_t flags : 5;
    uint8_t prolog_size;
    // unwind entries count
    uint8_t code_count;
    // register number that used as frame pointer
    uint8_t frame_reg : 4;
    // size in 16 uint8_t blocks
    uint8_t frame_reg_disp : 4;
    union
    {
      unwind_entry entries[1];
      uint16_t data[1];
    };
  };

  struct runtime_function
  {
    /*0x00*/ relative_virtual_address<const uint8_t> begin;
    /*0x04*/ relative_virtual_address<const uint8_t> end;
    /*0x08*/ relative_virtual_address<const unwind_info> unwind_struct;
  };

  union handler_info
  {
    struct
    {
      uint32_t exception : 1;
      uint32_t unwind : 1;
      uint32_t has_alignment : 1;
    };

    uint32_t all;
  };

  union exception_flag
  {
    struct
    {
      uint32_t non_continuable : 1;
      uint32_t unwinding : 1;
      uint32_t exit_unwind : 1;
      uint32_t stack_invalid : 1;
      uint32_t nested_call : 1;
      uint32_t target_unwind : 1;
      uint32_t collided_unwing : 1;
    };

    uint32_t all;
  };

  struct exception_record
  {
    // exception code
    uint32_t code;
    // type and condition of exception handling
    exception_flag flags;
    // if exception occurs in exception handler here will be a pointer to another exception record
    exception_record* next;
    // instruction that produced exception
    const uint8_t* address;
    // number of parameters in exception_information array
    uint32_t parameter_count;
  };

  struct catch_frame
  {
    uint64_t red_zone[4];

    machine_frame mach;
    catch_info catch_info;
  };

  enum class exception_disposition
  {
    continue_execution = 0,
    continue_search = 1,
    nested = 2,
    collided = 3,
    cxx_handler = 0x154d3c64,
  };

  struct x64_cpu_context;
  struct symbol {};

  using x64_frame_handler_t = exception_disposition(exception_record* exception_record, uint8_t* frame_ptr, x64_cpu_context*, void* dispatcher_context);
  using copy_ctor_t = void(void* self, void* other);
  using copy_ctor_virtual_base_t = void(void* self, void* other, int is_most_derived);

  class frame_walk_pdata
  {
  private:
    const uint8_t* image_base_;
    const runtime_function* functions_;
    uint32_t function_count_;
    uint32_t image_size_;

  public:
    explicit frame_walk_pdata(const uint8_t* image_base) noexcept;
    [[nodiscard]] const uint8_t* image_base() const noexcept;
    bool contains_address(const uint8_t* addr) const noexcept;
    const runtime_function* find_function_entry(const uint8_t* addr) const noexcept;

    static void unwind(const unwind_info& unwind_info, frame_walk_context& ctx, machine_frame& mach) noexcept;
    static frame_walk_pdata for_this_image() noexcept;
  };

  // Marked offsets are used by the nt!__GSHandlerCheck and nt!__C_speficic_handler
  struct dispatcher_context
  {
    // return address is pushed to stack by 'call _CxxThrowException'
    /*0x0*/ const uint8_t* last_instruction;
    /*0x8*/ const uint8_t* image_base;
    /*0x10*/ const runtime_function* fn;
    const frame_walk_pdata* pdata;
    throw_frame* throw_frame;
    void* padding;
    const uint8_t* handler;
    // language specific data
    /*0x38*/ const void* extra_data;
    void* history_table;
    /*0x48*/ uint32_t scope_index;
    void* cookie;
  };

  struct frame_handler
  {
    x64_frame_handler_t* handler;
    const void* data;
  };

  inline symbol unwind_cookie{};
  inline symbol rethrow_probe_cookie{};
  inline exception_record exc_record_cookie{ 0, {.unwinding = 1} };

  void terminate(const bug_check_context bsod);
  dispatcher_context make_context(void* cookie, throw_frame& frame, const frame_walk_pdata& pdata) noexcept;
  const unwind_info* execute_handler(dispatcher_context& ctx, frame_walk_context& cpu_ctx, machine_frame& mach) noexcept;
  extern "C" void verify_seh(NTSTATUS code, const void* addr, uint32_t flags) noexcept;

  template <typename Ty>
  relative_virtual_address<Ty> make_rva(Ty* ptr, const void* base) noexcept
  {
    return relative_virtual_address<Ty>{ ptr, base };
  }
}
