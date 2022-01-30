#pragma once
#include <stdint.h>
#include <ntddk.h>

namespace hh
{
  namespace hook
  {
    class hook_context;
  }

  namespace vmx
  {
    enum class vmcall_number : uint64_t
    {
      test = 0x1,
      vmxoff,
      change_page_attrib,
      invept_all_contexts,
      invept_single_context,
      unhook_all_pages,
      unhook_single_page,
    };

    struct invept_context { uint64_t phys_address; };

    extern "C" NTSTATUS __vmcall(vmcall_number call_num, uint64_t optional_param_1, uint64_t optional_param_2, uint64_t optional_param_3);

    template<class T> inline NTSTATUS vmcall(T) { __int2c(); }

    template <> inline NTSTATUS vmcall(hook::hook_context* context) noexcept
    { return __vmcall(vmcall_number::change_page_attrib, reinterpret_cast<uint64_t>(context), 0, 0); }

    template <> inline NTSTATUS vmcall(vmcall_number request) noexcept { return __vmcall(request, 0, 0, 0); }

    template <> inline NTSTATUS vmcall(invept_context context) noexcept
    { return __vmcall(vmcall_number::invept_single_context, context.phys_address, 0, 0); }
  }
}
