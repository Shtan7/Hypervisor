#pragma once
#include <string>
#include <deque>
#include <ntddk.h>
#include "win.hpp"

namespace hh
{
  namespace win
  {
    class system_module_information
    {
    private:
      void* raw_data_ptr_;
      std::deque<SYSTEM_MODULE_INFORMATION_ENTRY*> mods_;

    public:
      system_module_information();
      ~system_module_information();
      SYSTEM_MODULE_INFORMATION_ENTRY* get_module(std::string_view image_name) const noexcept;
    };
  }
}
