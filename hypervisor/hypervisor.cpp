#include "hypervisor.hpp"
#include "globals.hpp"
#include "msr.hpp"
#include "common.hpp"
#include <intrin.h>
#include <limits>
#include "dpc.hpp"
#include "vmcall.hpp"
#include "x86-64.hpp"
#include "vmexit_handler.hpp"
#include "pt_handler.hpp"
#include "vcpu.hpp"
#include "memory_manager.hpp"
#include "cpp_support.hpp"
#include "hooking.hpp"

namespace hh
{
  void hv_operations::initialize_hypervisor()
  {
    is_vmx_supported();

    globals::pt_handler = new ept::pt_handler;
    std::shared_ptr<hv_event_handlers::vmexit_handler> vmexit_handler = std::make_shared<hv_event_handlers::kernel_hook_assistant>();

    globals::pt_handler->initialize_ept();

    globals::vcpus = reinterpret_cast<vcpu*>(new uint8_t[sizeof(vcpu) * globals::processor_count]);

    for (int j = globals::processor_count; j--;)
    {
      new(&globals::vcpus[j]) vcpu(vmexit_handler);
    }

    globals::hook_builder = new hook::hook_builder;

    bool dpc_status = true;
    std::pair<vcpu*, bool&> dpc_argument = { globals::vcpus, dpc_status };

    // Allocate required structures and run vmxon on all logical cores
    KeGenericCallDpc([](PKDPC dpc, PVOID arg, PVOID system_argument_1, PVOID system_argument_2)
      {
        const int processor_id = KeGetCurrentProcessorNumber();

        auto* dpc_argument = reinterpret_cast<std::pair<vcpu*, bool&>*>(arg);
        auto& current_cpu = dpc_argument->first[processor_id];

        try
        {
          current_cpu.initialize_guest();
        }
        catch (std::exception& e)
        {
          KdPrint(("%s\n", e.what()));
          dpc_argument->second = false;
        }

        // Wait for all DPCs to synchronize at this point
        KeSignalCallDpcSynchronize(system_argument_2);

        // Mark the DPC as being complete
        KeSignalCallDpcDone(system_argument_1);

      }, &dpc_argument);

    if (!dpc_status)
    {
      throw std::exception{};
    }

    if (vmx::vmcall(vmx::vmcall_number::test) != STATUS_SUCCESS)
    {
      throw std::exception("Hypervisor initialized but test vmcall failed.");
    }
  }

  void hv_operations::is_vmx_supported()
  {
    common::cpuid_t data = {};
    x86::msr::feature_control_msr_t feature_control_msr = x86::msr::read<x86::msr::feature_control_msr_t>();

    __cpuid(reinterpret_cast<int*>(&data), 1);

    if (data.ecx & (1 << 5) == 0) // if CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported
    {
      throw std::exception{ "VMX operation is not supported: CPUID.1:ECX.VMX[bit 5] = 0." };
    }

    // BIOS lock check. If lock is 0 then vmxon causes a general protection exception
    if (feature_control_msr.fields.lock == 0)
    {
      feature_control_msr.fields.lock = true;
      feature_control_msr.fields.enable_vmxon = true;

      x86::msr::write<x86::msr::feature_control_msr_t>(feature_control_msr);
    }
    else if (feature_control_msr.fields.enable_vmxon == false)
    {
      throw std::exception{ "Intel vmx feature is locked in BIOS." };
    }
  }

  void hv_operations::deallocate_all_resources() noexcept
  {
    if (globals::pt_handler != nullptr)
    {
      delete globals::pt_handler;
    }

    if (globals::vcpus != nullptr)
    {
      for (int j = 0; j < globals::processor_count; j++)
      {
        globals::vcpus[j].~vcpu();
      }

      delete[] globals::vcpus;
    }

    if (globals::hook_builder != nullptr)
    {
      delete globals::hook_builder;
    }

    if (globals::mem_manager != nullptr)
    {
      globals::mem_manager = nullptr;
      delete globals::mem_manager;
    }

    __crt_deinit();
  }

  void hv_operations::terminate_hv() noexcept
  {
    KeIpiGenericCall([](uint64_t) -> uint64_t
      {
        vmx::vmcall(vmx::vmcall_number::vmxoff);

        return 0;
      }, 0);
  }

  void hv_operations::launch_on_all_cores(void(*fun)()) noexcept
  {
    KeIpiGenericCall([](uint64_t fun_) -> uint64_t
      {
        auto operation = reinterpret_cast<decltype(fun)>(fun_);
        operation();

        return 0;
      }, reinterpret_cast<uint64_t>(fun));
  }
}
