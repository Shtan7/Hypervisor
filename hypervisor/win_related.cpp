#include "win_related.hpp"

namespace hh
{
  namespace win
  {
    system_module_information::system_module_information()
    {
      // get required bytes number for the buff
      ULONG bytes = {};
      ZwQuerySystemInformation(SystemModuleInformation, nullptr, bytes, &bytes);

      auto* mods = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(new uint8_t[bytes]);
      ZwQuerySystemInformation(SystemModuleInformation, mods, bytes, &bytes);

      for (int j = 0; j < mods->Count; j++)
      {
        mods_.push_back(&mods->Module[j]);
      }

      raw_data_ptr_ = mods;
    }

    system_module_information::~system_module_information()
    {
      delete[] raw_data_ptr_;
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
}
