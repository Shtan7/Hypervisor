#include <ntddk.h>
#include "exc_common.hpp"

namespace exc
{
  uintptr_t member_ptr::apply(uintptr_t obj) const noexcept
  {
    if (vbtable_ptr_offset_)
    {
      uintptr_t vbtable_ptr = obj + vbtable_ptr_offset_;
      uintptr_t vbtable = *reinterpret_cast<const uintptr_t*>(vbtable_ptr);
      obj = vbtable_ptr + *reinterpret_cast<const uint32_t*>(vbtable + vbase_offset_);
    }

    return obj + member_offset_;
  }

  member_ptr::member_ptr(uint32_t vbase_offset, uint32_t vbtable_ptr_offset, uint32_t member_offset) noexcept
    : vbase_offset_{ vbase_offset }, vbtable_ptr_offset_{ vbtable_ptr_offset }, member_offset_{ member_offset } {}

  uint64_t& frame_walk_context::gp(uint8_t idx) noexcept
  {
    constexpr int8_t conv[16]
    {
      -1, -1, -1, 0, -1, 1, 2, 3, -1, -1, -1, -1, 4, 5, 6, 7,
    };

    const int8_t offs = conv[idx];

    if (offs < 0)
    {
      terminate({ bug_check_reason::corrupted_machine_state, offs });
    }

    return (&rbx)[offs];
  };

  void terminate(const bug_check_context bsod)
  {
    KeBugCheckEx(static_cast<uint32_t>(bsod.reason), bsod.arg_1, bsod.arg_2, bsod.arg_3, bsod.arg_4);
  }

  void* catch_info::get_exception_object() const noexcept
  {
    if (throw_info_if_owner)
    {
      return exception_object_or_link;
    }

    if (exception_object_or_link)
    {
      const auto* other = static_cast<const catch_info*>(exception_object_or_link);
      return other->exception_object_or_link;
    }

    return nullptr;
  }

  const throw_info* catch_info::get_throw_info() const noexcept
  {
    if (exception_object_or_link)
    {
      if (!throw_info_if_owner)
      {
        const auto* other = static_cast<const catch_info*>(this->exception_object_or_link);
        return other->throw_info_if_owner;
      }

      return throw_info_if_owner;
    }

    return nullptr;
  }

  static xmm_register& get_xmm(frame_walk_context& ctx, uint8_t idx) noexcept
  {
    if (idx < 6 || idx >= 16)
    {
      terminate({ bug_check_reason::corrupted_machine_state, idx });
    }

    return (&ctx.xmm6)[idx - 6];
  }

  template <class Ty>
  Ty get_unwind_data_as(const unwind_info& unwind_info, uint32_t idx) noexcept
  {
    const auto* data = reinterpret_cast<const uint8_t*>(unwind_info.data + idx);
    const auto value_ptr = reinterpret_cast<const Ty*>(data);

    return *value_ptr;
  }

  frame_walk_pdata::frame_walk_pdata(const uint8_t* image_base) noexcept : image_base_(image_base)
  {
    const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);

    do
    {
      BREAK_IF_FALSE(dos_hdr->e_magic == 0x5a4d);

      const auto* nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base_ + dos_hdr->e_lfanew);

      BREAK_IF_FALSE(nt_header->Signature == 0x4550);
      BREAK_IF_FALSE(nt_header->FileHeader.Machine == 0x8664);
      BREAK_IF_FALSE(nt_header->OptionalHeader.Magic == 0x20b);
      BREAK_IF_FALSE(nt_header->OptionalHeader.SizeOfHeaders >= dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS));
      BREAK_IF_FALSE(nt_header->OptionalHeader.SizeOfImage >= nt_header->OptionalHeader.SizeOfHeaders);

      BREAK_IF_FALSE(nt_header->OptionalHeader.NumberOfRvaAndSizes >= 4);
      BREAK_IF_FALSE(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size % sizeof(runtime_function) == 0);

      functions_ = reinterpret_cast<const runtime_function*>(image_base +
        nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
      function_count_ = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(runtime_function);
      image_size_ = nt_header->OptionalHeader.SizeOfImage;

      return;

    } while (false);

    terminate({ bug_check_reason::corrupted_pe_header });
  }

  frame_walk_pdata frame_walk_pdata::for_this_image() noexcept
  {
    return frame_walk_pdata{ &__ImageBase };
  }

  void frame_walk_pdata::unwind(const unwind_info& unwind_info, frame_walk_context& ctx, machine_frame& mach) noexcept
  {
    bool rip_updated = false;
    for (uint32_t idx = 0; idx < unwind_info.code_count; ++idx)
    {
      switch (const auto& entry = unwind_info.entries[idx]; entry.code)
      {
      case unwind_code::push_non_volatile_reg:
      {
        ctx.gp(entry.info) = *reinterpret_cast<const uint64_t*>(mach.rsp);
        mach.rsp += 8;

        break;
      }

      case unwind_code::alloc_large:
      {
        if (!entry.info)
        {
          mach.rsp += unwind_info.data[++idx] * 8;
        }
        else
        {
          mach.rsp += unwind_info.data[idx + 1];
          idx += 2;
        }

        break;
      }

      case unwind_code::alloc_small:
      {
        mach.rsp += entry.info * 8 + 8;

        break;
      }

      case unwind_code::set_frame_pointer:
      {
        mach.rsp = ctx.gp(unwind_info.frame_reg) - unwind_info.frame_reg_disp * 16;

        break;
      }

      case unwind_code::save_non_volatile_reg:
      {
        ctx.gp(entry.info) = *reinterpret_cast<const uint64_t*>(mach.rsp + unwind_info.data[++idx] * 8);

        break;
      }

      case unwind_code::save_far_non_volatile_reg:
      {
        ctx.gp(entry.info) = *reinterpret_cast<const uint64_t*>(mach.rsp + get_unwind_data_as<uint32_t>(unwind_info, +idx));
        idx += 2;

        break;
      }

      case unwind_code::epilog:
      {
        idx += 1;

        break;
      }

      case unwind_code::reserved_07:
      {
        idx += 2;

        break;
      }

      case unwind_code::same_xmm_128:
      {
        get_xmm(ctx, entry.info) = *reinterpret_cast<const xmm_register*>(mach.rsp + unwind_info.data[++idx] * 16);

        break;
      }

      case unwind_code::save_far_xmm_128:
      {
        get_xmm(ctx, entry.info) = *reinterpret_cast<const xmm_register*>(mach.rsp + unwind_info.data[idx + 1]);
        idx += 2;

        break;
      }

      case unwind_code::push_machine_frame:
      {
        mach.rsp += static_cast<uint64_t>(entry.info) * 8;
        mach.rip = *reinterpret_cast<const uint8_t**>(mach.rsp);
        mach.rsp = *reinterpret_cast<const uint64_t*>(mach.rsp + 24);
        rip_updated = true;

        break;
      }
      }
    }

    if (!rip_updated)
    {
      mach.rip = *reinterpret_cast<const uint8_t**>(mach.rsp);
      mach.rsp += 8;
    }
  }

  const uint8_t* frame_walk_pdata::image_base() const noexcept
  {
    return image_base_;
  }

  bool frame_walk_pdata::contains_address(const uint8_t* addr) const noexcept
  {
    return image_base_ <= addr && addr - image_base_ < image_size_;
  }

  const runtime_function* frame_walk_pdata::find_function_entry(const uint8_t* addr) const noexcept
  {
    if (!contains_address(addr))
    {
      terminate({ bug_check_reason::no_matching_exception_handler });
    }

    const relative_virtual_address pc_rva{ make_rva(addr, image_base_) };
    uint32_t left_bound{ 0 };
    uint32_t right_bound = function_count_;

    while (left_bound < right_bound)
    {
      const uint32_t idx = {left_bound + (right_bound - left_bound) / 2};

      if (const auto* fn_ptr = functions_ + idx; pc_rva < fn_ptr->begin)
      {
        right_bound = idx;
      }
      else if (fn_ptr->end <= pc_rva)
      {
        left_bound = idx + 1;
      }
      else
      {
        return fn_ptr;
      }
    }

    return nullptr;
  }

  dispatcher_context make_context(void* cookie, throw_frame& frame, const frame_walk_pdata& pdata) noexcept
  {
    dispatcher_context ctx{};
    ctx.image_base = pdata.image_base();
    ctx.pdata = &pdata;
    ctx.throw_frame = &frame;
    ctx.cookie = cookie;

    return ctx;
  }
}
