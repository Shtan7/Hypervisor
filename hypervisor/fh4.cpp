#include <ntddk.h>
#include "exc_common.hpp"

namespace exc
{
  struct gs_check_data
  {
    uint32_t _00;
  };

  struct gs4_data
  {
    relative_virtual_address<uint8_t> func_info;
    gs_check_data gs_check_data;
  };

  union attributes
  {
    struct
    {
      uint8_t is_catch_funclet : 1;
      uint8_t has_multiple_funclets : 1;
      uint8_t bbt : 1; // Flags set by Basic Block Transformations
      uint8_t has_unwind_map : 1;
      uint8_t has_try_block_map : 1;
      uint8_t ehs : 1;
      uint8_t is_noexcept : 1;
    };

    uint8_t all;
  };

  union catch_block_flag
  {
    struct
    {
      uint8_t has_type_flags : 1;
      uint8_t has_type_info : 1;
      uint8_t has_catch_var : 1;
      uint8_t image_rva : 1;
      uint8_t continuation_addr_count : 2; // 0x30
    };

    uint8_t all;
  };

  union catch_flag
  {
    struct
    {
      uint32_t is_const : 1;
      uint32_t is_volatile : 1;
      uint32_t is_unaligned : 1;
      uint32_t is_reference : 1;
      uint32_t is_resumable : 1;
      uint32_t reserved_0 : 1;
      uint32_t is_ellipsis : 1;
      uint32_t reserved_1 : 24;
      uint32_t is_complus_eh : 1;
    };

    uint32_t all;
  };

  struct exc_info
  {
    attributes flags;
    uint32_t bbt_flags;
    relative_virtual_address<const uint8_t> unwind_graph;
    relative_virtual_address<const uint8_t> try_blocks;
    relative_virtual_address<const uint8_t> regions;
    relative_virtual_address<uint8_t*> primary_frame_ptr;
  };

  static int32_t read_int(const uint8_t** data) noexcept
  {
    // XXX alignment
    const int32_t result = *reinterpret_cast<const int32_t*>(*data);
    *data += 4;

    return result;
  }

  // delta decoding
  static uint32_t read_unsigned(const uint8_t** data) noexcept
  {
    const uint8_t enc_type{ static_cast<uint8_t>((*data)[0] & 0xf) };

    static constexpr uint8_t lengths[] =
    {
      1, 2, 1, 3, 1, 2, 1, 4, 1, 2, 1, 3, 1, 2, 1, 5,
    };

    static constexpr uint8_t shifts[] =
    {
      0x19, 0x12, 0x19, 0x0b, 0x19, 0x12, 0x19, 0x04,
      0x19, 0x12, 0x19, 0x0b, 0x19, 0x12, 0x19, 0x00,
    };

    const uint8_t length = lengths[enc_type];

    // XXX we're in UB land here
    uint32_t result{ *reinterpret_cast<const uint32_t*>(*data + length - 4) };
    result >>= shifts[enc_type];

    *data += length;
    return result;
  }

  template <typename Ty>
  static relative_virtual_address<Ty> read_rva(const uint8_t** data) noexcept
  {
    uint32_t offset = read_int(data);

    return relative_virtual_address<Ty>{offset};
  }

  struct unwind_edge
  {
    enum class type
    {
      trivial = 0,
      object_offset = 1,
      object_ptr_offset = 2,
      function = 3,
    };

    uint32_t target_offset;
    type target_type;
    relative_virtual_address<void()> destroy_fn;
    relative_virtual_address<void> object;

    static unwind_edge read(const uint8_t** p) noexcept
    {
      unwind_edge result;

      uint32_t target_offset_and_type = read_unsigned(p);

      result.target_type = static_cast<unwind_edge::type>(target_offset_and_type & 3);
      result.target_offset = target_offset_and_type >> 2;
      result.destroy_fn = result.target_type != type::trivial ? read_rva<void()>(p) : 0;
      result.object = relative_virtual_address<void>(result.target_type == type::object_offset
        || result.target_type == type::object_ptr_offset ? read_unsigned(p) : 0);

      return result;
    }

    static void skip(const uint8_t** p) noexcept
    {
      (void)read(p);
    }
  };

  void verify_seh_in_cxx_handler(NTSTATUS code, const void* addr, uint32_t flags, uint32_t unwind_info, const void* image_base) noexcept
  {
    KdPrint((
      "SEH exception caught in CXX handler! Code: 0x%08X, address: %p, "
      "flags: %u, function "
      "unwind info offset: %u, image_base: %p)\n",
      code, addr, flags, unwind_info, image_base));

    if (const bool unwinding = exception_flag{ .unwinding = 1 }.all & flags; unwinding)
    {
      terminate({ bug_check_reason::unwinding_non_cxx_frame, reinterpret_cast<int64_t>(addr), reinterpret_cast<int64_t>(image_base) });
    }
  }

  static int32_t lookup_region(const exc_info* eh_info, const uint8_t* image_base,
    relative_virtual_address<const uint8_t> fn, const uint8_t* control_pc) noexcept
  {
    if (!eh_info->regions)
    {
      return -1;
    }

    const auto pc = make_rva(control_pc, image_base + fn);
    const uint8_t* p = image_base + eh_info->regions;

    int32_t state = -1;
    const uint32_t region_count = read_unsigned(&p);
    relative_virtual_address<const uint8_t> fn_rva = 0;

    for (uint32_t idx = 0; idx != region_count; ++idx)
    {
      fn_rva += read_unsigned(&p);

      if (pc < fn_rva)
      {
        break;
      }

      state = read_unsigned(&p) - 1;
    }

    return state;
  }

  static void load_exception_info(exc_info& eh_info, const uint8_t* data, const uint8_t* image_base, const runtime_function& fn) noexcept
  {
    const attributes flags = { .all = *data++ };
    eh_info.flags = flags;

    if (flags.all & attributes{ .bbt = 1 }.all)
    {
      eh_info.bbt_flags = read_unsigned(&data);
    }

    if (flags.all & attributes{ .has_unwind_map = 1 }.all)
    {
      eh_info.unwind_graph = read_rva<const uint8_t>(&data);
    }

    if (flags.all & attributes{ .has_try_block_map = 1 }.all)
    {
      eh_info.try_blocks = read_rva<const uint8_t>(&data);
    }

    // Find the correct one if this is a separated segment
    if (flags.all & attributes{ .has_multiple_funclets = 1 }.all)
    {
      const uint8_t* funclet_map = image_base + read_rva<const uint8_t>(&data);

      const uint32_t count = read_unsigned(&funclet_map);

      // By default, an entry not found in the table corresponds to no
      // states associated with the segment
      eh_info.regions = 0;
      for (uint32_t idx = 0; idx != count; ++idx)
      {
        const auto fn_rva = read_rva<const void>(&funclet_map);
        const auto regions = read_rva<const uint8_t>(&funclet_map);

        if (fn_rva.value() == fn.begin.value())
        {
          eh_info.regions = regions;
          break;
        }
      }
    }
    // Otherwise, the table is directly encoded in the function info
    else
    {
      eh_info.regions = read_rva<const uint8_t>(&data);
    }

    if (flags.all & attributes{ .is_catch_funclet = 1 }.all)
    {
      eh_info.primary_frame_ptr = relative_virtual_address<uint8_t*>(read_unsigned(&data));
    }
  }

  void probe_for_exception(const frame_walk_pdata& pdata, throw_frame& frame) noexcept
  {
    dispatcher_context ctx = { make_context(&rethrow_probe_cookie, frame, pdata) };
    auto& [_, probe_ctx, probe_mach, ci]{frame};

    for (;;)
    {
      const unwind_info* unwind_info = execute_handler(ctx, probe_ctx, probe_mach);

      if (ci.exception_object_or_link)
      {
        break;
      }

      pdata.unwind(*unwind_info, probe_ctx, probe_mach);
    }
  }

  static void copy_to_catch_block(const uint8_t* image_base, const catchable_type* catchable,
    void* catch_var, void* exception_object) noexcept
  {
    if (catchable->properties.all & catchable_property{ .is_simple_type = 1 }.all)
    {
      memcpy(catch_var, exception_object, catchable->size);
    }
    else if (!catchable->copy_fn)
    {
      const uintptr_t address = catchable->offset.apply(reinterpret_cast<uintptr_t>(exception_object));
      memcpy(catch_var, reinterpret_cast<void*>(address), catchable->size);
    }
    else if(catchable->properties.all & catchable_property{ .has_virtual_base = 1 }.all)
    {
      auto* raw_copy_ctor = const_cast<uint8_t*>(image_base + catchable->copy_fn);
      auto* copy_ctor = reinterpret_cast<copy_ctor_virtual_base_t*>(raw_copy_ctor);
      copy_ctor(catch_var, exception_object, 1 /* is most derived */);
    }
    else
    {
      auto* raw_copy_ctor = const_cast<uint8_t*>(image_base + catchable->copy_fn);
      auto* copy_ctor = reinterpret_cast<copy_ctor_t*>(raw_copy_ctor);
      copy_ctor(catch_var, exception_object);
    }
  }

  static void transfer_to_catch_block(const uint8_t* image_base, catch_flag adjectives,
    const catchable_type* catchable, void* catch_var, void* exception_object) noexcept
  {
    if (!(catchable->properties.all & catchable_property{ .by_reference_only = 1 }.all) || adjectives.all & catch_flag{ .is_reference = 1 }.all)
    {
      if (!(adjectives.all & catch_flag{ .is_reference = 1 }.all))
      {
        copy_to_catch_block(image_base, catchable, catch_var, exception_object);
      }
      else
      {
        auto* catch_var_holder = static_cast<void**>(catch_var);
        *catch_var_holder = exception_object;
      }
    }
  }

  static bool process_catch_block_unchecked(const uint8_t* image_base, catch_flag adjectives,
    const type_info* match_type, void* catch_var, void* exception_object, const catchable_type_list* catchable_list) noexcept
  {
    const auto* catchables = catchable_list->types;

    for (uint32_t idx = 0; idx < catchable_list->count; ++idx)
    {
      const catchable_type* catchable = image_base + catchables[idx];

      if (const type_info* type_descriptor = image_base + catchable->desc; type_descriptor == match_type)
      {
        transfer_to_catch_block(image_base, adjectives, catchable, catch_var, exception_object);

        return true;
      }
    }

    return false;
  }

  bool process_catch_block(const uint8_t* image_base, catch_flag adjectives, const type_info* match_type, void* catch_var,
    void* exception_object, const throw_info& throw_info) noexcept
  {
    if (adjectives.all & catch_flag{ .is_ellipsis = 1 }.all)
    {
      return true;
    }

    /*
    * Returns false, if throw has one of IsConst, IsVolatile, or IsUnaligned
    * flags, and the catch block hasn't
    */
    if (throw_info.attributes.all & throw_flags{ {.is_const = 1, .is_volatile = 1, .is_unaligned = 1} }.all & (~adjectives.all))
    {
      return false;
    }

    return process_catch_block_unchecked(image_base, adjectives, match_type, catch_var, exception_object,
      image_base + throw_info.catchables);
  }

  void destroy_objects(const uint8_t* image_base, relative_virtual_address<const uint8_t> unwind_graph_rva,
    uint8_t* frame_ptr, int32_t initial_state, int32_t final_state) noexcept
  {
    const uint8_t* unwind_graph = image_base + unwind_graph_rva;
    const uint32_t unwind_node_count = read_unsigned(&unwind_graph);

    if (initial_state < 0 || static_cast<uint32_t>(initial_state) >= unwind_node_count)
    {
      terminate({ bug_check_reason::corrupted_eh_unwind_data, initial_state, unwind_node_count });
    }

    const uint8_t *current_edge = unwind_graph, *last_edge = current_edge;

    for (int32_t idx = 0; idx != initial_state; ++idx)
    {
      unwind_edge::skip(&current_edge);

      if (idx == final_state)
      {
        last_edge = current_edge;
      }
    }

    if (initial_state == final_state)
    {
      last_edge = current_edge;
    }

    for (;;)
    {
      const uint8_t* unwind_struct = current_edge;

      const uint32_t target_offset_and_type = read_unsigned(&unwind_struct);
      const uint32_t target_offset = target_offset_and_type >> 2;

      if (!target_offset)
      {
        terminate({ bug_check_reason::corrupted_eh_unwind_data, initial_state, unwind_node_count, reinterpret_cast<int64_t>(current_edge) });
      }

      const auto edge_type = static_cast<unwind_edge::type>(target_offset_and_type & 3);
      switch (edge_type)
      {
      case unwind_edge::type::trivial:
      {
        break;
      }
      case unwind_edge::type::object_offset:
      {
        const auto destroy_fn = image_base + read_rva<void(uint8_t*)>(&unwind_struct);
        uint8_t* obj = frame_ptr + read_unsigned(&unwind_struct);
        destroy_fn(obj);

        break;
      }
      case unwind_edge::type::object_ptr_offset:
      {
        const auto destroy_fn = image_base + read_rva<void(uint8_t*)>(&unwind_struct);
        uint8_t* obj = *reinterpret_cast<uint8_t**>(frame_ptr + read_unsigned(&unwind_struct));
        destroy_fn(obj);

        break;
      }
      case unwind_edge::type::function:
      {
        const auto destroy_fn = image_base + read_rva<void(void*, uint8_t*)>(&unwind_struct);
        destroy_fn(reinterpret_cast<void*>(destroy_fn), frame_ptr);

        break;
      }
      }

      if (current_edge - last_edge < target_offset)
      {
        break;
      }

      current_edge -= target_offset;
    }
  }

  static exception_disposition fh(exception_record*, uint8_t* frame_ptr, x64_cpu_context*, dispatcher_context* ctx) noexcept
  {
    if (ctx->cookie == &rethrow_probe_cookie)
    {
      return exception_disposition::cxx_handler;
    }

    if (ctx->cookie != &unwind_cookie)
    {
      return exception_disposition::continue_search;
    }

    const uint8_t* image_base = ctx->pdata->image_base();
    throw_frame* throw_frame = ctx->throw_frame;
    catch_info& catch_info = throw_frame->catch_info;

    const gs4_data* handler_data = static_cast<const gs4_data*>(ctx->extra_data);
    const uint8_t* compressed_data = image_base + handler_data->func_info;

    exc_info eh_info = {};
    load_exception_info(eh_info, compressed_data, image_base, *ctx->fn);

    uint8_t* primary_frame_ptr;
    int32_t initial_state;

    if (catch_info.primary_frame_ptr >= frame_ptr)
    {
      primary_frame_ptr = catch_info.primary_frame_ptr;
      initial_state = static_cast<int32_t>(catch_info.unwind_context);
    }
    else
    {
      initial_state = lookup_region(&eh_info, image_base, ctx->fn->begin, throw_frame->mach.rip);

      if(eh_info.flags.all & attributes{ .is_catch_funclet = 1 }.all)
      {
        primary_frame_ptr = *(frame_ptr + eh_info.primary_frame_ptr);
      }
      else
      {
        primary_frame_ptr = frame_ptr;
      }
    }

    int32_t target_state = -1;

    if (eh_info.try_blocks && initial_state >= 0)
    {
      const auto* throw_info = catch_info.get_throw_info();

      const uint8_t* p = image_base + eh_info.try_blocks;
      const uint32_t try_block_count = read_unsigned(&p);
      for (uint32_t try_block_idx = 0; try_block_idx != try_block_count; ++try_block_idx)
      {
        const uint32_t try_low = read_unsigned(&p);
        const uint32_t try_high = read_unsigned(&p);

        [[maybe_unused]] uint32_t catch_high = read_unsigned(&p);

        const auto handlers = read_rva<const uint8_t>(&p);

        if (try_low > static_cast<uint32_t>(initial_state) || static_cast<uint32_t>(initial_state) > try_high)
        {
          continue;
        }

        if (!throw_info)
        {
          probe_for_exception(*ctx->pdata, *throw_frame);
          throw_info = throw_frame->catch_info.get_throw_info();
        }

        const uint8_t* q{ image_base + handlers };
        const uint32_t handler_count = read_unsigned(&q);

        for (uint32_t handler_idx = 0; handler_idx != handler_count; ++handler_idx)
        {
          catch_block_flag handler_flags = { .all = *q++ };
          const catch_flag type_flags =
          {
            (handler_flags.all & catch_block_flag{.has_type_flags = 1 }.all) ? catch_flag{ .all = read_unsigned(&q) } : catch_flag{} 
          };

          relative_virtual_address<type_info const> type = handler_flags.all & catch_block_flag{ .has_type_info = 1 }.all
            ? read_rva<type_info const>(&q) : 0;

          const uint32_t continuation_addr_count = handler_flags.continuation_addr_count;

          const auto catch_var = handler_flags.all & catch_block_flag{.has_catch_var = 1 }.all
            ? relative_virtual_address<void>{read_unsigned(&q)} : 0;

          const auto handler = read_rva<const uint8_t>(&q);

          if (handler_flags.all & catch_block_flag{ .image_rva = 1 }.all)
          {
            for (uint32_t k = 0; k != continuation_addr_count; ++k)
            {
              catch_info.continuation_address[k] = image_base + read_rva<const uint8_t>(&q);
            }
          }
          else
          {
            const uint8_t* fn = image_base + ctx->fn->begin;

            for (uint32_t k = 0; k != continuation_addr_count; ++k)
            {
              catch_info.continuation_address[k] = fn + read_unsigned(&q);
            }
          }

          if (process_catch_block(image_base, type_flags, image_base + type, primary_frame_ptr + catch_var,
            throw_frame->catch_info.get_exception_object(), *throw_info))
          {
            ctx->handler = image_base + handler;
            catch_info.primary_frame_ptr = primary_frame_ptr;
            target_state = try_low - 1;
            catch_info.unwind_context = target_state;

            break;
          }
        }

        if (ctx->handler)
        {
          break;
        }
      }
    }

    if (target_state < initial_state)
    {
      destroy_objects(image_base, eh_info.unwind_graph, frame_ptr, initial_state, target_state);
    }

    return exception_disposition::cxx_handler;
  }

  EXTERN_C exception_disposition __CxxFrameHandler4(exception_record* exc_record, uint8_t* frame_ptr,
    x64_cpu_context* cpu_ctx, dispatcher_context* dispatcher_ctx) noexcept
  {
    if (exc_record != &exc_record_cookie)
    {
      verify_seh_in_cxx_handler(exc_record->code, exc_record->address,
        exc_record->flags.all, dispatcher_ctx->fn->unwind_struct.value(), dispatcher_ctx->image_base);

      return exception_disposition::continue_search;
    }

    return fh(exc_record, frame_ptr, cpu_ctx, dispatcher_ctx);
  }

  EXTERN_C exception_disposition __GSHandlerCheck_EH4(exception_record* exc_record, uint8_t* frame_ptr,
    x64_cpu_context* cpu_ctx, dispatcher_context* ctx) noexcept
  {
    // No cookie check because driver will be manual mapped :)
    return __CxxFrameHandler4(exc_record, frame_ptr, cpu_ctx, ctx);
  }
}
