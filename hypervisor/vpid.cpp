#include "vpid.hpp"

namespace hh
{
  namespace vmx
  {
    void invvpid(invvpid_type type, invvpid_descriptor* descriptor) noexcept
    {
      if (descriptor == nullptr)
      {
        static invvpid_descriptor zero_descriptor = {};
        descriptor = &zero_descriptor;
      }

      __invvpid(static_cast<uint32_t>(type), descriptor);
    }

    void invvpid_individual_address(uint16_t vpid, uint64_t linear_address) noexcept
    {
      invvpid_descriptor descriptor = { vpid, 0, linear_address };
      invvpid(invvpid_type::invvpid_individual_address, &descriptor);
    }

    void invvpid_single_context(uint16_t vpid) noexcept
    {
      invvpid_descriptor descriptor = { vpid, 0, 0 };
      invvpid(invvpid_type::invvpid_single_context, &descriptor);
    }

    void invvpid_all_contexts() noexcept
    {
      invvpid(invvpid_type::invvpid_all_context, nullptr);
    }

    void invvpid_single_context_retaining_globals(uint16_t vpid) noexcept
    {
      invvpid_descriptor descriptor = { vpid, 0, 0 };
      invvpid(invvpid_type::invvpid_single_context_retaining_globals, &descriptor);
    }
  }
}
