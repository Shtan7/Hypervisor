#pragma once
#include <stdint.h>

namespace hh
{
  namespace vmx
  {
    enum class invvpid_type
    {
      invvpid_individual_address = 0x00000000,
      invvpid_single_context = 0x00000001,
      invvpid_all_context = 0x00000002,
      invvpid_single_context_retaining_globals = 0x00000003
    };

    struct invvpid_descriptor
    {
      uint64_t vpid : 16;
      uint64_t reserved : 48;
      uint64_t linear_address;
    };

    inline constexpr uint32_t vpid_tag = 0x1;

    extern "C" uint8_t __invvpid(uint32_t type, void* descriptors) noexcept;
    void invvpid_individual_address(uint16_t vpid, uint64_t linear_address) noexcept;
    void invvpid_single_context(uint16_t vpid) noexcept;
    void invvpid_all_contexts() noexcept;
    void invvpid_single_context_retaining_globals(uint16_t vpid) noexcept;
  }
}
