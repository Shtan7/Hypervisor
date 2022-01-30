#pragma once
#include "delete_constructors.hpp"
#include "common.hpp"
#include <vector>

namespace hh
{
  class vcpu;

  namespace hv_event_handlers
  {
    class vmexit_handler abstract : non_relocatable
    {
      friend class vcpu;
      using vm_handler = void(vmexit_handler::*)(common::guest_regs* regs, vcpu* cpu_obj);

    private:
      vm_handler handlers_[66];

    private:
      static bool handlers_dispatcher(common::guest_regs* regs) noexcept;
      static void vm_resume() noexcept;
      static void vmxoff_handler() noexcept;
      static uint64_t get_stack_pointer_for_vmxoff() noexcept;
      static uint64_t get_instruction_pointer_for_vmxoff() noexcept;
      static void vmexit_entry() noexcept;

      virtual void handle_exception_nmi(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_external_interrupt(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_triple_fault(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_init(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_sipi(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_io_smi(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_other_smi(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_pending_virt_intr(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_pending_virt_nmi(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_task_switch(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_cpuid(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_getsec(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_hlt(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_invd(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_invlpg(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_rdpmc(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_rdtsc(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_rsm(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmcall(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmclear(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmlaunch(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmptrld(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmptrst(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmread(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmresume(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmwrite(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmxoff(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmxon(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_cr_access(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_dr_access(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_io_instruction(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_msr_read(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_msr_write(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_invalid_guest_state(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_msr_loading(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_mwait_instruction(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_monitor_trap_flag(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_monitor_instruction(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_pause_instruction(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_mce_during_vmentry(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_tpr_below_threshold(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_apic_access(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_access_gdtr_or_idtr(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_access_ldtr_or_tr(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_ept_violation(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_ept_misconfig(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_invept(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_rdtscp(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_vmx_preemption_timer_expired(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_invvpid(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_wbinvd(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_xsetbv(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_apic_write(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_rdrand(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_invpcid(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_rdseed(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_pml_full(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_xsaves(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_xrstors(common::guest_regs* regs, vcpu* cpu_obj);
      virtual void handle_pcommit(common::guest_regs* regs, vcpu* cpu_obj);

      // Do absolutely nothing.
      void handler_stub(common::guest_regs* regs) noexcept;

    protected:

      // RAII simd registers saver.
      struct fx_state_saver
      {
        common::fxsave_area* fxsave_area;
        fx_state_saver(common::fxsave_area* ptr) noexcept;
        ~fx_state_saver() noexcept;
      };

    public:
      vmexit_handler();
      virtual ~vmexit_handler() = default;
    };

    class kernel_hook_assistant : public vmexit_handler
    {
    private:
      void handle_vmx_command() const noexcept;
      void execute_vmxoff_sequence(vcpu* cpu_obj);
      void restore_registers() const noexcept;

      void handle_triple_fault(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmclear(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmlaunch(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmptrld(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmptrst(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmread(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmresume(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmwrite(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmxoff(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmxon(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_cr_access(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_msr_read(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_msr_write(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_cpuid(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_io_instruction(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_ept_violation(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_ept_misconfig(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_vmcall(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_monitor_trap_flag(common::guest_regs* regs, vcpu* cpu_obj) override;
      void handle_hlt(common::guest_regs* regs, vcpu* cpu_obj) override;
    };
  }
}
