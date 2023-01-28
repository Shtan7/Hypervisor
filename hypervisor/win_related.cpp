#include "win_related.hpp"

namespace hh::win
{
  system_module_information::system_module_information()
  {
    // get required bytes number for the buff
    ULONG bytes = {};
    ZwQuerySystemInformation(SystemModuleInformation, nullptr, bytes, &bytes);

    raw_data_ptr_ = std::make_unique<uint8_t[]>(bytes);
    auto* mods = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(raw_data_ptr_.get());
    ZwQuerySystemInformation(SystemModuleInformation, mods, bytes, &bytes);

    mods_.reserve(mods->Count);

    for (int j = 0; j < mods->Count; j++)
    {
      mods_.push_back(&mods->Module[j]);
    }
  }

  SYSTEM_MODULE_INFORMATION_ENTRY* system_module_information::get_module(std::string_view image_name) const noexcept
  {
    for (const auto entry : mods_)
    {
      if (entry != nullptr)
      {
        if (entry->ImageName != nullptr)
        {
          if (strstr(entry->ImageName, image_name.data()))
          {
            return entry;
          }
        }
      }
    }

    return nullptr;
  }
}
