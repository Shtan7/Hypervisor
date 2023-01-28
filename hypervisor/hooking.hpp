#pragma once
#include <ntddk.h>
#include "lde.hpp"
#include "common.hpp"
#include <cstdint>
#include <string>
#include "delete_constructors.hpp"
#include <map>

namespace hh
{
  namespace x86
  {
    struct cr3_t;
  }

  namespace ept
  {
    struct hooked_page_detail;
  }

  // What access bits should be in EPT entry.
  union page_attribs
  {
    struct
    {
      uint8_t read : 1;
      uint8_t write : 1;
      uint8_t exec : 1;
    };

    uint8_t all;
  };

  namespace hook
  {
    struct pattern_entry
    {
      std::string_view pattern;
      std::string_view mask;
    };

    namespace patterns
    {
      inline constexpr pattern_entry ssdt_shadow_table{ "\x4C\x8D\x1D\x00\x00\x00\x00\xF7\x43\x00\x00\x00\x00\x00", "xxx????xx?????" };
    }

    namespace pointers
    {
      extern "C" inline NTSTATUS(*NtCreateFileOrig)(
        PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
        ULONG ShareAccess, ULONG CreateDisposition,
        ULONG CreateOptions, PVOID EaBuffer,
        ULONG EaLength) = nullptr;
    }

    enum class ssdt_numbers : uint32_t
    {
      NtCreateFile = 0x55,
    };

    /*
     * Auxiliary class that provides hook information
     * for the hook builder.
     */
    class hook_context
    {
      using self = hook_context;
      friend class hook_builder;

    public:
      uint8_t* target_address_;
      void* hook_function_;
      void** orig_function_;
      x86::cr3_t old_cr3_;
      page_attribs attributes;

    public:
      hook_context(x86::cr3_t cr3 = {}) noexcept;
      hook_context(const hook_context&) noexcept = default;
      hook_context(hook_context&&) noexcept = default;
      hook_context& operator=(const hook_context&) noexcept = default;
      hook_context& operator=(hook_context&&) noexcept = default;
      self& set_target_address(void* target_address) noexcept;
      self& set_read() noexcept;
      self& set_write() noexcept;
      self& set_exec() noexcept;
      self& set_functions(void* hook_function, void** orig_function) noexcept;
      virtual ~hook_context() noexcept;
    };

    // Performs ept hooks.
    class hook_builder : non_relocatable
    {
    protected:
      std::map<uint64_t, ept::hooked_page_detail> hooked_pages_list_;
      disassembler lde_;

    protected:
      void ept_hook_internal(hook_context* context);
      void hook_instruction_in_memory(ept::hooked_page_detail* hooked_page, hook_context* context);
      void write_absolute_jmp(uint8_t* target_buffer, uint64_t where_to_jmp) const noexcept;
      void write_absolute_ret(uint8_t* target_buffer, uint64_t where_to_jmp) const noexcept;

    public:
      void unhook_all_pages();
      void unhook_single_page(uint64_t physical_address);
      void ept_hook(hook_context& context);
      ept::hooked_page_detail* get_hooked_page_info(uint64_t guest_physical_address) noexcept;
    };

    // Get address of kernel function by SSDT.
    void* get_address_by_ssdt(ssdt_numbers ssdt_function_number, bool is_win32k, void* pe_base);
    // Find address of signature.
    void* find_pattern(void* start_address, uint64_t size_of_scan_section, std::string_view pattern, std::string_view mask) noexcept;
  }
}
