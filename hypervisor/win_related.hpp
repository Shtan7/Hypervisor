#pragma once
#include <string>
#include <vector>
#include "win.hpp"
#include <memory>
#include "delete_constructors.hpp"

namespace hh::win
{
  class system_module_information : non_copyable
  {
  private:
    std::unique_ptr<uint8_t[]> raw_data_ptr_;
    std::vector<SYSTEM_MODULE_INFORMATION_ENTRY*> mods_;

  public:
    system_module_information();
    system_module_information(system_module_information&&) noexcept = default;
    system_module_information& operator=(system_module_information&&) noexcept = default;
    ~system_module_information() noexcept = default;
    SYSTEM_MODULE_INFORMATION_ENTRY* get_module(std::string_view image_name) const noexcept;
  };
}
