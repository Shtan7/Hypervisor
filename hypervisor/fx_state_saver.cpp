#include "common.hpp"
#include "vmexit_handler.hpp"

namespace hh::hv_event_handlers
{
  vmexit_handler::fx_state_saver::fx_state_saver(common::fxsave_area* ptr) noexcept : fxsave_area{ ptr }
  {
    *fxsave_area = common::fxsave_area{};
    _fxsave64(fxsave_area);
  }

  vmexit_handler::fx_state_saver::~fx_state_saver() noexcept
  {
    _fxrstor64(fxsave_area);
  }
}
