#include <ntddk.h>
#include "exc_common.hpp"
#include <intrin.h>

namespace exc
{
  frame_handler get_frame_handler(const uint8_t* image_base, const unwind_info& info, size_t unwind_node_count) noexcept {
    /*
    * Immediately after the array of unwind entries in memory is RVAs to the
    * exception handler and handler-specific data emitted by the compiler
    *
    * union {
    *      uint32_t exception_handler;
    *      uint32_t function_entry;
    * };
    * uint32_t exception_data[];
    *
    * Type of exception handler  Type of the associated data
    *   __C_specific_handler        Scope table
    *   __GSHandlerCheck            GS data
    *   __GSHandlerCheck_SEH        Scope table + GS data
    *   __CxxFrameHandler3          RVA to FuncInfo
    *   __CxxFrameHandler4          RVA to FuncInfo
    *   __GSHandlerCheck_EH         RVA to FuncInfo + GS data
    *
    * Also see
    * https://yurichev.com/mirrors/RE/Recon-2012-Skochinsky-Compiler-Internals.pdf
    */
    using handler_rva_t = relative_virtual_address<x64_frame_handler_t>;

    const auto* exception_handler_and_data = reinterpret_cast<const uint8_t*>(info.data + unwind_node_count);

    const auto* handler_rva = reinterpret_cast<const handler_rva_t*>(exception_handler_and_data);
    const uint8_t* data = exception_handler_and_data + sizeof(handler_rva_t);

    return { image_base + *handler_rva, data };
  }

  static void prepare_for_non_cxx_handler(dispatcher_context& ctx, frame_walk_context& cpu_ctx, machine_frame& mach) noexcept
  {
    cpu_ctx.dummy_rsp = mach.rsp;
    cpu_ctx.dummy_rip = mach.rip;

    ctx.last_instruction = mach.rip;
    ctx.history_table = nullptr;

    /*
    * We do not yet support the continuation of unwinding if an exception was
    * thrown in the SEH __finally block (this means that the destructor threw the
    * exception)
    */
    ctx.scope_index = 0;
  }

  const unwind_info* execute_handler(dispatcher_context& ctx, frame_walk_context& cpu_ctx, machine_frame& mach) noexcept
  {
    const auto& pdata = *ctx.pdata;
    const uint8_t* image_base = pdata.image_base();

    ctx.fn = pdata.find_function_entry(mach.rip);

    const unwind_info* unwind_struct = image_base + ctx.fn->unwind_struct;
    constexpr handler_info handler_mask = { {.exception = 1, .unwind = 1} };

    if (const handler_info flags = { .all = unwind_struct->flags }; flags.all & handler_mask.all)
    {
      // The number of active slots is always odd
      const auto unwind_slots = (static_cast<size_t>(unwind_struct->code_count) + 1ull) & ~1ull;

      frame_handler temp = get_frame_handler(image_base, *unwind_struct, unwind_slots);

      x64_frame_handler_t* handler = temp.handler;
      const void* extra_data = temp.data;

      if (!handler)
      {
        KdPrint(("C++ exception must have an associated handler\n"));
        __int2c();
      }

      ctx.extra_data = extra_data;

      uint8_t* frame_ptr = reinterpret_cast<uint8_t*>(unwind_struct->frame_reg ? cpu_ctx.gp(unwind_struct->frame_reg) : mach.rsp);

      prepare_for_non_cxx_handler(ctx, cpu_ctx, mach);

      [[maybe_unused]] exception_disposition exc_action = handler(&exc_record_cookie, frame_ptr, reinterpret_cast<x64_cpu_context*>(&cpu_ctx), &ctx);
    }

    return unwind_struct;
  }

  extern "C" const uint8_t* __cxx_dispatch_exception(void* exception_object, const throw_info* throw_info, throw_frame& frame) noexcept
  {
    const frame_walk_pdata pdata = frame_walk_pdata::for_this_image();
    dispatcher_context ctx = make_context(&unwind_cookie, frame, pdata);
    frame_walk_context& cpu_ctx = frame.ctx;
    machine_frame& mach = frame.mach;

    catch_info& ci = frame.catch_info;
    ci.exception_object_or_link = exception_object;
    ci.throw_info_if_owner = throw_info;
    ci.primary_frame_ptr = nullptr;

    for (;;)
    {
      const auto* unwind_info = execute_handler(ctx, cpu_ctx, mach);

      if (ctx.handler)
      {
        return ctx.handler;
      }

      pdata.unwind(*unwind_info, cpu_ctx, mach);
    }
  }

  void verify_seh(NTSTATUS code, const void* addr, uint32_t flags) noexcept
  {
    KdPrint(("SEH exception caught with flag EXCEPTION_UNWIND! Code: 0x%08X, address: %p, flags: %u\n",
      code, addr, flags));

    if(const bool unwinding = exception_flag{ .all = flags }.all & exception_flag{ .unwinding = 1 }.all; unwinding)
    {
      terminate({bug_check_reason::unwinding_non_cxx_frame, code, reinterpret_cast<int64_t>(addr)});
    }
  }

  extern "C" void __cxx_destroy_exception(catch_info & ci) noexcept
  {
    if (ci.throw_info_if_owner && ci.throw_info_if_owner->destroy_exc_obj)
    {
      const auto destructor = &__ImageBase + ci.throw_info_if_owner->destroy_exc_obj;
      destructor(ci.exception_object_or_link);
    }
  }

  extern "C" exception_disposition __cxx_call_catch_frame_handler(exception_record* exception_record, uint8_t* frame_ptr,
    x64_cpu_context*, void* dispatcher_ctx)
  {
    if (exception_record != &exc_record_cookie)
    {
      verify_seh(exception_record->code, exception_record->address, exception_record->flags.all);
      return exception_disposition::continue_search;
    }

    auto* ctx = static_cast<dispatcher_context*>(dispatcher_ctx);
    auto* frame = reinterpret_cast<catch_frame*>(frame_ptr);

    catch_info& ci = ctx->throw_frame->catch_info;

    if (ctx->cookie == &rethrow_probe_cookie)
    {
      if (!frame->catch_info.exception_object_or_link)
      {
        terminate({bug_check_reason::corrupted_exception_handler,
          reinterpret_cast<int64_t>(ctx->cookie), reinterpret_cast<int64_t>(frame) });
      }

      if (frame->catch_info.throw_info_if_owner)
      {
        ci.exception_object_or_link = &frame->catch_info;
      }
      else
      {
        ci.exception_object_or_link = frame->catch_info.exception_object_or_link;
      }
    }
    else if (ctx->cookie == &unwind_cookie)
    {
      if (!ci.exception_object_or_link || ci.exception_object_or_link == &frame->catch_info)
      {
        ci.exception_object_or_link = frame->catch_info.exception_object_or_link;
        ci.throw_info_if_owner = frame->catch_info.throw_info_if_owner;
      }
      else
      {
        __cxx_destroy_exception(frame->catch_info);
      }

      ci.primary_frame_ptr = frame->catch_info.primary_frame_ptr;
      ci.unwind_context = frame->catch_info.unwind_context;
    }
    else
    {
      return exception_disposition::continue_search;
    }

    return exception_disposition::cxx_handler;
  }

  extern "C" exception_disposition __cxx_seh_frame_handler(exception_record * exc_record, uint8_t*, x64_cpu_context*, void*)
  {
    if (exc_record != &exc_record_cookie)
    {
      verify_seh(exc_record->code, exc_record->address, exc_record->flags.all);
    }

    return exception_disposition::continue_search;
  }
}
