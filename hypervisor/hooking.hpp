#pragma once
#include <ntddk.h>
#include "lde.hpp"
#include "common.hpp"
#include <stdint.h>
#include <list>
#include <string>
#include "win.hpp"
#include "delete_constructors.hpp"

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

  namespace hook
  {
    struct pattern_entry
    {
      std::string_view pattern;
      std::string_view mask;
    };

    namespace patterns
    {
      inline constexpr pattern_entry ssdt_shadow_table{ "\x4C\x8D\x1D\x00\x00\x00\x00\xF7\x43\x78\x80\x00\x00\x00", "xxx????xxxxxxx" };
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
      common::directory_base_guard* dir_base = {};
      uint8_t* target_address;
      void* hook_function;
      void** orig_function;
      x86::cr3_t new_cr3 = {};
      uint32_t page_hook_mask;

    protected:
      virtual void pre_hook_callback();
      virtual void post_hook_callback();

    public:
      hook_context(void* target_address) noexcept;
      self& unset_read() noexcept;
      self& unset_write() noexcept;
      self& unset_exec() noexcept;
      self& set_functions(void* hook_function, void** orig_function) noexcept;
      virtual ~hook_context() noexcept = default;
    };

    // Performs ept hooks.
    class hook_builder : non_relocatable
    {
    protected:
      std::list<ept::hooked_page_detail> hooked_pages_list_;
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
