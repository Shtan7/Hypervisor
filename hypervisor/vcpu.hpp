#pragma once
#include <memory>
#include "delete_constructors.hpp"
#include "vmx.hpp"
#include "ept.hpp"
#include "x86-64.hpp"
#include "exit_qualification.hpp"
#include "exit_reason.hpp"
#include "instruction_error.hpp"
#include "common.hpp"

namespace hh
{
  namespace hv_event_handlers
  {
    class vmexit_handler;
  }

  namespace ept
  {
    class pt_handler;
  }

  class vcpu : non_relocatable
  {
  private:
    vmx::virtual_machihe_state_t guest_state_;
    std::shared_ptr<hv_event_handlers::vmexit_handler> vmexit_handler_;
    common::fxsave_area* fxsave_area_;

  private:

    /* Read only fields */

    void page_fault_error_code_mask(ept::pagefault_error_code mask) noexcept;
    ept::pagefault_error_code page_fault_error_code_mask() const noexcept;

    void page_fault_error_code_match(ept::pagefault_error_code match) noexcept;
    ept::pagefault_error_code page_fault_error_code_match() const noexcept;

    void vmcs_link_pointer(uint64_t link_pointer) noexcept;

    void cpu_based_vm_exec_control(x86::msr::vmx_procbased_ctls_t procbased_ctls, x86::msr::vmx_basic_msr_t basic_msr) noexcept;
    x86::msr::vmx_procbased_ctls_t cpu_based_vm_exec_control() const noexcept;

    void secondary_vm_exec_control(x86::msr::vmx_procbased_ctls2_t procbased_ctls2) noexcept;
    x86::msr::vmx_procbased_ctls2_t secondary_vm_exec_control() const noexcept;

    void pin_based_vm_exec_control(x86::msr::vmx_pinbased_ctls_t pinbased_ctls, x86::msr::vmx_basic_msr_t basic_msr) noexcept;
    x86::msr::vmx_pinbased_ctls_t pin_based_vm_exec_control() const noexcept;

    void vm_exit_controls(x86::msr::vmx_exit_ctls_t exit_ctls, x86::msr::vmx_basic_msr_t basic_msr) noexcept;
    x86::msr::vmx_exit_ctls_t vm_exit_controls() const noexcept;

    void vm_entry_controls(x86::msr::vmx_entry_ctls_t entry_ctls, x86::msr::vmx_basic_msr_t basic_msr) noexcept;
    x86::msr::vmx_entry_ctls_t vm_entry_controls() const noexcept;

    uint64_t msr_bitmap() const noexcept;
    void msr_bitmap(uint64_t phys_address) noexcept;

    uint64_t ept_pointer() const noexcept;
    void ept_pointer(uint64_t value) noexcept;

    uint64_t vpid() const noexcept;
    void vpid(uint64_t value) noexcept;

    vmx::exception_bitmap exception_bitmap() const noexcept;
    void exception_bitmap(vmx::exception_bitmap exception_bitmap) noexcept;

  public:

    /* Exit state */

    vmx::instruction_error vm_instruction_error() const noexcept;
    vmx::exit_qualification_t exit_qualification() const noexcept;
    uint32_t exit_instruction_length() const noexcept;
    vmx::exit_reason vmexit_reason() const noexcept;

    bool launch_status() const noexcept;
    void launch_status(bool bit) noexcept;

    bool vmx_root_status() const noexcept;
    void vmx_root_status(bool bit) noexcept;

    uint64_t vmxoff_state_guest_rip() const noexcept;
    void vmxoff_state_guest_rip(uint64_t rip) noexcept;

    uint64_t vmxoff_state_guest_rsp() const noexcept;
    void vmxoff_state_guest_rsp(uint64_t rsp) noexcept;

    bool vmxoff_executed() const noexcept;
    void vmxoff_executed(bool bit) noexcept;

    uint64_t exit_guest_physical_address() const noexcept;
    uint64_t exit_guest_linear_address() const noexcept;

    common::fxsave_area* fxsave_area() noexcept;

  private:

    /* Host state */

    x86::cr0_t host_cr0() const noexcept;
    void host_cr0(x86::cr0_t cr0) noexcept;
    x86::cr3_t host_cr3() const noexcept;
    void host_cr3(x86::cr3_t cr3) noexcept;
    x86::cr4_t host_cr4() const noexcept;
    void host_cr4(x86::cr4_t cr4) noexcept;

    uint64_t host_rsp() const noexcept;
    void host_rsp(uint64_t rsp) noexcept;
    uint64_t host_rip() const noexcept;
    void host_rip(uint64_t rip) noexcept;

    x86::gdtr_t host_gdtr() const noexcept;
    void host_gdtr(x86::gdtr_t gdtr) noexcept;
    x86::idtr_t host_idtr() const noexcept;
    void host_idtr(x86::idtr_t idtr) noexcept;

    x86::segment_t<x86::cs_t> host_cs() const noexcept;
    void host_cs(x86::segment_t<x86::cs_t> cs) noexcept;
    x86::segment_t<x86::ds_t> host_ds() const noexcept;
    void host_ds(x86::segment_t<x86::ds_t> ds) noexcept;
    x86::segment_t<x86::es_t> host_es() const noexcept;
    void host_es(x86::segment_t<x86::es_t> es) noexcept;
    x86::segment_t<x86::fs_t> host_fs() const noexcept;
    void host_fs(x86::segment_t<x86::fs_t> fs) noexcept;
    x86::segment_t<x86::gs_t> host_gs() const noexcept;
    void host_gs(x86::segment_t<x86::gs_t> gs) noexcept;
    x86::segment_t<x86::ss_t> host_ss() const noexcept;
    void host_ss(x86::segment_t<x86::ss_t> ss) noexcept;
    x86::segment_t<x86::tr_t> host_tr() const noexcept;
    void host_tr(x86::segment_t<x86::tr_t> tr) noexcept;

    void host_sysenter_cs(uint64_t value) noexcept;
    uint64_t host_sysenter_cs() const noexcept;
    void host_sysenter_eip(uint64_t value) noexcept;
    uint64_t host_sysenter_eip() const noexcept;
    void host_sysenter_esp(uint64_t value) noexcept;
    uint64_t host_sysenter_esp() const noexcept;

  public:

    /* Guest state */

    void tsc_offset(uint64_t value) noexcept;
    uint64_t tsc_offset() const noexcept;
    void tsc_multiplier(uint64_t value) noexcept;
    uint64_t tsc_multiplier() const noexcept;

    x86::cr0_t guest_cr0() const noexcept;
    void guest_cr0(x86::cr0_t cr0) noexcept;
    x86::cr3_t guest_cr3() const noexcept;
    void guest_cr3(x86::cr3_t cr3) noexcept;
    x86::cr4_t guest_cr4() const noexcept;
    void guest_cr4(x86::cr4_t cr4) noexcept;

    x86::dr7_t guest_dr7() const noexcept;
    void guest_dr7(x86::dr7_t dr7) noexcept;
    x86::msr::debugctl_t guest_debugctl() const noexcept;
    void guest_debugctl(x86::msr::debugctl_t debugctl) noexcept;

    x86::cr0_t cr0_guest_host_mask() const noexcept;
    void cr0_guest_host_mask(x86::cr0_t cr0) noexcept;
    x86::cr0_t cr0_shadow() const noexcept;
    void cr0_shadow(x86::cr0_t cr0) noexcept;
    x86::cr4_t cr4_guest_host_mask() const noexcept;
    void cr4_guest_host_mask(x86::cr4_t cr4) noexcept;
    x86::cr4_t cr4_shadow() const noexcept;
    void cr4_shadow(x86::cr4_t cr4) noexcept;

    uint64_t guest_rsp() const noexcept;
    void guest_rsp(uint64_t rsp) noexcept;
    uint64_t guest_rip() const noexcept;
    void guest_rip(uint64_t rip) noexcept;
    x86::rflags_t guest_rflags() const noexcept;
    void guest_rflags(x86::rflags_t rflags) noexcept;

    x86::gdtr_t guest_gdtr() const noexcept;
    void guest_gdtr(x86::gdtr_t gdtr) noexcept;
    x86::idtr_t guest_idtr() const noexcept;
    void guest_idtr(x86::idtr_t idtr) noexcept;

    x86::segment_t<x86::cs_t> guest_cs() const noexcept;
    void guest_cs(x86::segment_t<x86::cs_t> cs) noexcept;
    x86::segment_t<x86::ds_t> guest_ds() const noexcept;
    void guest_ds(x86::segment_t<x86::ds_t> ds) noexcept;
    x86::segment_t<x86::es_t> guest_es() const noexcept;
    void guest_es(x86::segment_t<x86::es_t> es) noexcept;
    x86::segment_t<x86::fs_t> guest_fs() const noexcept;
    void guest_fs(x86::segment_t<x86::fs_t> fs) noexcept;
    x86::segment_t<x86::gs_t> guest_gs() const noexcept;
    void guest_gs(x86::segment_t<x86::gs_t> gs) noexcept;
    x86::segment_t<x86::ss_t> guest_ss() const noexcept;
    void guest_ss(x86::segment_t<x86::ss_t> ss) noexcept;
    x86::segment_t<x86::tr_t> guest_tr() const noexcept;
    void guest_tr(x86::segment_t<x86::tr_t> tr) noexcept;
    x86::segment_t<x86::ldtr_t> guest_ldtr() const noexcept;
    void guest_ldtr(x86::segment_t<x86::ldtr_t> ldtr) noexcept;

    void guest_sysenter_cs(uint64_t value) noexcept;
    uint64_t guest_sysenter_cs() const noexcept;
    void guest_sysenter_eip(uint64_t value) noexcept;
    uint64_t guest_sysenter_eip() const noexcept;
    void guest_sysenter_esp(uint64_t value) noexcept;
    uint64_t guest_sysenter_esp() const noexcept;

    /* Common */

    std::shared_ptr<hv_event_handlers::vmexit_handler> vmexit_handler() const noexcept;
    void vmexit_handler(std::shared_ptr<hv_event_handlers::vmexit_handler> ptr) noexcept;
    ept::hooked_page_detail** mtf_restore_point() noexcept;
    void set_monitor_trap_flag(bool set) noexcept;
    void resume_to_next_instruction() noexcept;
    void skip_instruction(bool set) noexcept;
    bool skip_instruction() noexcept;

  private:

    /* Setup methods section */

    void allocate_vmx_on_region();
    void allocate_vmcs_region();
    void enable_vmx_operation() const noexcept;
    void allocate_vmm_stack();
    void allocate_msr_bitmap();
    void set_msr_bitmap(uint64_t msr, bool read_detection, bool write_detection);
    uint32_t adjust_controls(uint32_t ctl, uint32_t msr) const noexcept;
    void save_state_and_start_virtualization() noexcept;
    void virtualize_current_system(void* stack_ptr);
    static void restore_state() noexcept;
    void clear_vmcs_state();
    void load_vmcs();
    void setup_vmcs(void* stack_ptr) noexcept;
    void allocate_vmx_regions();

  public:
    vcpu(std::shared_ptr<hv_event_handlers::vmexit_handler> exit_handler) noexcept;
    void initialize_guest();
    ~vcpu();
  };
}
