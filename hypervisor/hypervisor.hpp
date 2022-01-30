#pragma once
namespace hh
{
  namespace hv_operations
  {
    // Check MSR bits that signals about vmx support.
    void is_vmx_supported();
    void initialize_hypervisor();
    // Call vmxoff on all cores.
    void terminate_hv() noexcept;
    // Launch function on all cores with IPI_LEVEL.
    void launch_on_all_cores(void(*fun)()) noexcept;
    // Free all heap allocated resources.
    void deallocate_all_resources() noexcept;
  }
}
