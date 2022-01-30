#include "lde.hpp"
#include <Zydis/Decoder.h>
#include <exception>

namespace hh
{
  disassembler::disassembler() noexcept
  {
    ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  }

  uint32_t disassembler::get_instructions_length(uint8_t* target_address, uint32_t min_acceptable_length) const
  {
    constexpr uint32_t max_disasm_range = 64;

    uint32_t result_length = {};

    ZydisDecodedInstruction instruction = {};
    ZydisDecoderContext context = {};

    while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder_, &context, target_address, max_disasm_range, &instruction)))
    {
      target_address += instruction.length;
      result_length += instruction.length;

      if (result_length >= min_acceptable_length)
      {
        return result_length;
      }
    }

    throw std::exception{ "Failed to find required instructions size." };
  }
}
