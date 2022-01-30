#include "invept.hpp"

namespace hh
{
  namespace vmx
  {
    uint8_t invept(invept_type type, invept_desc* descriptor) noexcept
    {
      if (!descriptor)
      {
        static invept_desc zero_descriptor = {};
        descriptor = &zero_descriptor;
      }

      return __invept(static_cast<uint32_t>(type), descriptor);
    }

    uint8_t invept_all_contexts() noexcept
    {
      return invept(invept_type::invept_all_contexts, nullptr);
    }

    uint8_t invept_single_context(uint64_t ept_pointer) noexcept
    {
      invept_desc descriptor = {};
      descriptor.ept_pointer = ept_pointer;
      descriptor.reserved = 0;

      return invept(invept_type::invept_single_context, &descriptor);
    }
  }
}
