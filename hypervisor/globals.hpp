#pragma once

namespace hh
{
  class memory_manager;
  class vcpu;

  namespace ept
  {
    class pt_handler;
  }

  namespace hook
  {
    class hook_builder;
  }
}

namespace globals
{
  inline hh::memory_manager* mem_manager = {};
  inline hh::ept::pt_handler* pt_handler = {};
  inline int processor_count = {};
  inline hh::hook::hook_builder* hook_builder = {};
  inline hh::vcpu* vcpus = {};
}
