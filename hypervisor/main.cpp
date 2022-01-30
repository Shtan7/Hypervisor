#include <ntddk.h>
#include "memory_manager.hpp"
#include "globals.hpp"
#include "hypervisor.hpp"
#include "cpp_support.hpp"
#include "vcpu.hpp"
#include "x86-64.hpp"
#include "hooking.hpp"
#include "win_related.hpp"
#include "hook_functions.hpp"

using namespace hh;

void setup_hooks()
{
  win::system_module_information system_modules = {};
  auto* system_process_base = system_modules.get_module("ntoskrnl");

  if (system_process_base == nullptr)
  {
    throw std::exception{ "Cannot get system process base." };
  }

 /*
  * Remember that this syscall number is only valid for specific Windows versions. Visit
  * https://hfiref0x.github.io/syscalls.html to get a correct one.
  */

  globals::hook_builder->ept_hook(
    hook::hook_context{ hook::get_address_by_ssdt(hook::ssdt_numbers::NtCreateFile, false, system_process_base->Base) }
    .unset_exec()
    .set_functions(hh::NtCreateFile, reinterpret_cast<void**>(&hh::hook::pointers::NtCreateFileOrig)));
}

NTSTATUS entry_point()
{
  __crt_init();

  globals::processor_count = KeQueryActiveProcessorCount(0);

  try
  {
    globals::mem_manager = new buddy_allocator(buddy_allocator::c_total_number_of_pages * PAGE_SIZE);

    hv_operations::initialize_hypervisor();
    setup_hooks();
  }
  catch (std::exception& e)
  {
    /*
    If initialization failed then free all memory
    allocations and spoof vmx bit in cr4 register.
    */

    if (globals::vcpus != nullptr)
    {
      if (globals::vcpus[KeGetCurrentProcessorNumber()].launch_status())
      {
        hh::hv_operations::terminate_hv();
      }
    }

    hv_operations::launch_on_all_cores([]()
      {
        x86::cr4_t cr4 = x86::read<x86::cr4_t>();
        cr4.flags.vmx_enable = 0;
        x86::write<x86::cr4_t>(cr4);
      });

    KdPrint(("Hypervisor init failed. %s\n", e.what()));

    hv_operations::deallocate_all_resources();

    return STATUS_FAILED_DRIVER_ENTRY;
  }

  KdPrint(("Hypervisor successfully loaded.\n"));

  return STATUS_SUCCESS;
}
