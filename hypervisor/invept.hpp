#pragma once
#include <ntddk.h>
#include <stdint.h>

namespace hh
{
  namespace vmx
  {
    enum class invept_type
    {
      invept_single_context = 0x00000001,
      invept_all_contexts = 0x00000002
    };

    struct invept_desc
    {
      uint64_t ept_pointer;
      uint64_t reserved;
    };

    extern "C" uint8_t __invept(uint32_t type, void* descriptors) noexcept;
    uint8_t invept(invept_type type, invept_desc* descriptor) noexcept;
    uint8_t invept_all_contexts() noexcept;
    uint8_t invept_single_context(uint64_t ept_pointer) noexcept;
  }
}
