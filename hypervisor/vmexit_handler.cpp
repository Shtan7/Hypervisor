#include "vmexit_handler.hpp"
#include <intrin.h>
#include "globals.hpp"
#include "x86-64.hpp"
#include "vpid.hpp"
#include "vmcall.hpp"
#include "vcpu.hpp"
#include "pt_handler.hpp"
#include "hooking.hpp"
#include "invept.hpp"
#include "vpid.hpp"

namespace hh
{
  namespace hv_event_handlers
  {
    vmexit_handler::fx_state_saver::fx_state_saver(common::fxsave_area* ptr) noexcept : fxsave_area{ ptr }
    {
      *fxsave_area = common::fxsave_area{};
      _fxsave64(fxsave_area);
    }

    vmexit_handler::fx_state_saver::~fx_state_saver() noexcept
    {
      _fxrstor64(fxsave_area);
    }

    bool vmexit_handler::handlers_dispatcher(common::guest_regs* regs) noexcept
    {
      vcpu* current_vcpu = &globals::vcpus[KeGetCurrentProcessorNumber()];
      fx_state_saver saver{ current_vcpu->fxsave_area() };
      regs->fx_area = current_vcpu->fxsave_area();
      vmexit_handler* this_ptr = current_vcpu->vmexit_handler().get();
      const uint64_t vmexit_reason = static_cast<uint16_t>(current_vcpu->vmexit_reason());

      current_vcpu->skip_instruction(true);
      current_vcpu->vmx_root_status(true);
      (this_ptr->*(this_ptr->handlers_[vmexit_reason]))(regs, current_vcpu);

      if (current_vcpu->skip_instruction())
      {
        current_vcpu->resume_to_next_instruction();
      }

      current_vcpu->vmx_root_status(false);
      return current_vcpu->vmxoff_executed();
    }

    uint64_t vmexit_handler::get_instruction_pointer_for_vmxoff() noexcept
    {
      return globals::vcpus[KeGetCurrentProcessorNumber()].vmxoff_state_guest_rip();
    }

    uint64_t vmexit_handler::get_stack_pointer_for_vmxoff() noexcept
    {
      return globals::vcpus[KeGetCurrentProcessorNumber()].vmxoff_state_guest_rsp();
    }

    void vmexit_handler::vm_resume() noexcept
    {
      __vmx_vmresume();

      // If vmresume succeed will never be here
      uint64_t error_code = {};
      __vmx_vmread((size_t)vmx::vmcs_fields::vm_instruction_error, &error_code);
      __vmx_off();

      KdPrint(("vmresume error: 0x%llx\n", error_code));
      __int2c();
    }

    vmexit_handler::vmexit_handler()
      : handlers_
    {
      &vmexit_handler::handle_exception_nmi,
      &vmexit_handler::handle_external_interrupt,
      &vmexit_handler::handle_triple_fault,
      &vmexit_handler::handle_init,
      &vmexit_handler::handle_sipi,
      &vmexit_handler::handle_io_smi,
      &vmexit_handler::handle_other_smi,
      &vmexit_handler::handle_pending_virt_intr,
      &vmexit_handler::handle_pending_virt_nmi,
      &vmexit_handler::handle_task_switch,
      &vmexit_handler::handle_cpuid,
      &vmexit_handler::handle_getsec,
      &vmexit_handler::handle_hlt,
      &vmexit_handler::handle_invd,
      &vmexit_handler::handle_invlpg,
      &vmexit_handler::handle_rdpmc,
      &vmexit_handler::handle_rdtsc,
      &vmexit_handler::handle_rsm,
      &vmexit_handler::handle_vmcall,
      &vmexit_handler::handle_vmclear,
      &vmexit_handler::handle_vmlaunch,
      &vmexit_handler::handle_vmptrld,
      &vmexit_handler::handle_vmptrst,
      &vmexit_handler::handle_vmread,
      &vmexit_handler::handle_vmresume,
      &vmexit_handler::handle_vmwrite,
      &vmexit_handler::handle_vmxoff,
      &vmexit_handler::handle_vmxon,
      &vmexit_handler::handle_cr_access,
      &vmexit_handler::handle_dr_access,
      &vmexit_handler::handle_io_instruction,
      &vmexit_handler::handle_msr_read,
      &vmexit_handler::handle_msr_write,
      &vmexit_handler::handle_invalid_guest_state,
      &vmexit_handler::handle_msr_loading,
      &vmexit_handler::handle_mwait_instruction,
      &vmexit_handler::handle_monitor_trap_flag,
      &vmexit_handler::handle_monitor_instruction,
      &vmexit_handler::handle_pause_instruction,
      &vmexit_handler::handle_mce_during_vmentry,
      &vmexit_handler::handle_tpr_below_threshold,
      &vmexit_handler::handle_apic_access,
      &vmexit_handler::handle_access_gdtr_or_idtr,
      &vmexit_handler::handle_access_ldtr_or_tr,
      &vmexit_handler::handle_ept_violation,
      &vmexit_handler::handle_ept_misconfig,
      &vmexit_handler::handle_invept,
      &vmexit_handler::handle_rdtscp,
      &vmexit_handler::handle_vmx_preemption_timer_expired,
      &vmexit_handler::handle_invvpid,
      &vmexit_handler::handle_wbinvd,
      &vmexit_handler::handle_xsetbv,
      &vmexit_handler::handle_apic_write,
      &vmexit_handler::handle_rdrand,
      &vmexit_handler::handle_invpcid,
      &vmexit_handler::handle_rdseed,
      &vmexit_handler::handle_pml_full,
      &vmexit_handler::handle_xsaves,
      &vmexit_handler::handle_xrstors,
      &vmexit_handler::handle_pcommit
    }
    {}

    void vmexit_handler::handler_stub(common::guest_regs* regs) noexcept
    {
      (void)(regs);
    }

    void vmexit_handler::handle_exception_nmi(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_external_interrupt(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_triple_fault(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_init(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_sipi(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_io_smi(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_other_smi(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_pending_virt_intr(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_pending_virt_nmi(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_task_switch(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_cpuid(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_getsec(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_hlt(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_invd(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_invlpg(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_rdpmc(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_rdtsc(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_rsm(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmcall(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmclear(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmlaunch(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmptrld(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmptrst(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmread(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmresume(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmwrite(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmxoff(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmxon(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_cr_access(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_dr_access(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_io_instruction(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_msr_read(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_msr_write(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_invalid_guest_state(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_msr_loading(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_mwait_instruction(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_monitor_trap_flag(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_monitor_instruction(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_pause_instruction(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_mce_during_vmentry(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_tpr_below_threshold(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_apic_access(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_access_gdtr_or_idtr(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_access_ldtr_or_tr(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_ept_violation(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_ept_misconfig(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_invept(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_rdtscp(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_vmx_preemption_timer_expired(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_invvpid(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_wbinvd(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_xsetbv(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_apic_write(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_rdrand(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_invpcid(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_rdseed(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_pml_full(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_xsaves(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_xrstors(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }
    void vmexit_handler::handle_pcommit(common::guest_regs* regs, vcpu* cpu_obj) { handler_stub(regs); }

    void kernel_hook_assistant::handle_triple_fault(common::guest_regs* regs, vcpu* cpu_obj)
    {
      KdPrint(("Triple fault error occured.\n"));
    }

    void kernel_hook_assistant::handle_vmx_command() const noexcept
    {
      x86::rflags_t rflags = {};
      vmx::vmread(vmx::vmcs_fields::guest_rflags, rflags);
      rflags.flags.carry_flag = 1; // cf=1 indicate vmx instructions fail
      vmx::vmwrite(vmx::vmcs_fields::guest_rflags, rflags);
    }

    // we do not support vmx commands
    void kernel_hook_assistant::handle_vmclear(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmlaunch(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmptrld(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmptrst(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmread(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmresume(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmwrite(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmxoff(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }
    void kernel_hook_assistant::handle_vmxon(common::guest_regs* regs, vcpu* cpu_obj) { handle_vmx_command(); }

    void kernel_hook_assistant::handle_cr_access(common::guest_regs* regs, vcpu* cpu_obj)
    {
      const auto exit_info = cpu_obj->exit_qualification();
      uint64_t* reg_ptr = &regs->rax + exit_info.mov_cr.flags.gp_register;

      /* Because its RSP and as we didn't save RSP correctly (because of pushes) so we have make it points to the GUEST_RSP */
      if (exit_info.mov_cr.flags.gp_register == 4)
      {
        uint64_t guest_rsp = {};
        vmx::vmread(vmx::vmcs_fields::guest_rsp, guest_rsp);
        *reg_ptr = guest_rsp;
      }

      switch(exit_info.mov_cr.flags.access_type)
      {
        case vmx::exit_qualification_mov_cr_t::access_to_cr:
        {
          switch (exit_info.mov_cr.flags.cr_number)
          {
            case 0:
            {
              vmx::vmwrite(vmx::vmcs_fields::guest_cr0, *reg_ptr);
              vmx::vmwrite(vmx::vmcs_fields::cr0_read_shadow, *reg_ptr);

              break;
            }

            case 3:
            {
              // 63 bit invalidates TLB entries. On modern win it will cause bsod.
              vmx::vmwrite(vmx::vmcs_fields::guest_cr3, *reg_ptr & ~(1ull << 63));
              vmx::invvpid_single_context(vmx::vpid_tag);

              break;
            }

            case 4:
            {
              vmx::vmwrite(vmx::vmcs_fields::guest_cr4, *reg_ptr);
              vmx::vmwrite(vmx::vmcs_fields::cr4_read_shadow, *reg_ptr);

              break;
            }

            default:
            {
              KdPrint(("Unsupported cr register access detected. Register num %d\n", exit_info.mov_cr.flags.cr_number));

              break;
            }

          }

          break;
        }

        case vmx::exit_qualification_mov_cr_t::access_from_cr:
        {
          switch (exit_info.mov_cr.flags.cr_number)
          {
            case 0:
            {
              vmx::vmwrite(vmx::vmcs_fields::guest_cr0, reg_ptr);

              break;
            }

            case 3:
            {
              vmx::vmwrite(vmx::vmcs_fields::guest_cr3, reg_ptr);

              break;
            }

            case 4:
            {
              vmx::vmwrite(vmx::vmcs_fields::guest_cr4, reg_ptr);

              break;
            }

            default:
            {
              KdPrint(("Unsupported cr register access detected. Register num %d\n", exit_info.mov_cr.flags.cr_number));

              break;
            }
          }

          break;
        }

        default:
        {
          KdPrint(("Unsopported cr register operation detected. Operation type %d\n", exit_info.mov_cr.flags.access_type));

          break;
        }
      }
    }

    void kernel_hook_assistant::handle_msr_read(common::guest_regs* regs, vcpu* cpu_obj)
    {
      x86::msr::register_content msr = {};

      if (regs->rcx <= x86::msr::low_msr_high_range || (x86::msr::high_msr_low_range <= regs->rcx && regs->rcx <= x86::msr::high_msr_high_range)
        || (regs->rcx >= x86::msr::reserved_msr_range_low && regs->rcx <= x86::msr::reserved_msr_range_hi))
      {
        msr.all = __readmsr(regs->rcx);
      }

      regs->rax = msr.low;
      regs->rdx = msr.high;
    }

    void kernel_hook_assistant::handle_msr_write(common::guest_regs* regs, vcpu* cpu_obj)
    {
      x86::msr::register_content msr;

      if (regs->rcx <= x86::msr::low_msr_high_range || (x86::msr::high_msr_low_range <= regs->rcx && regs->rcx <= x86::msr::high_msr_high_range)
        || (regs->rcx >= x86::msr::reserved_msr_range_low && regs->rcx <= x86::msr::reserved_msr_range_hi))
      {
        msr.low = static_cast<uint32_t>(regs->rax);
        msr.high = static_cast<uint32_t>(regs->rdx);

        __writemsr(regs->rcx, msr.all);
      }
    }

    void kernel_hook_assistant::handle_cpuid(common::guest_regs* regs, vcpu* cpu_obj)
    {
      int32_t cpu_info[4];

      __cpuidex(cpu_info, static_cast<int32_t>(regs->rax), static_cast<int32_t>(regs->rcx));

      regs->rax = cpu_info[0];
      regs->rbx = cpu_info[1];
      regs->rcx = cpu_info[2];
      regs->rdx = cpu_info[3];
    }

    void kernel_hook_assistant::handle_io_instruction(common::guest_regs* regs, vcpu* cpu_obj)
    {
      KdPrint(("We don't support io instructions.\n"));
    }

    void kernel_hook_assistant::execute_vmxoff_sequence(vcpu* cpu_obj)
    {
      /* Before __vmx_off you must restore
       * fs_base, gs_base, gdt, idt and cr3
       * to guest values or you will get BSOD
       * from patch guard.
       */

      uint64_t guest_rsp = cpu_obj->guest_rsp();
      uint64_t guest_rip = cpu_obj->guest_rip();
      x86::cr3_t guest_cr3 = cpu_obj->guest_cr3();
      const uint64_t exit_instruction_length = cpu_obj->exit_instruction_length();

      x86::write<x86::cr3_t>(guest_cr3);
      guest_rip += exit_instruction_length;

      cpu_obj->vmxoff_state_guest_rip(guest_rip);
      cpu_obj->vmxoff_state_guest_rsp(guest_rsp);
      cpu_obj->vmxoff_executed(true);

      restore_registers();

      vmx::invvpid_all_contexts();
      vmx::invept_all_contexts();

      __vmx_off();

      cpu_obj->launch_status(false);

      x86::cr4_t cr4 = x86::read<x86::cr4_t>();
      cr4.flags.vmx_enable = 0;
      x86::write<x86::cr4_t>(cr4);
    }

    void kernel_hook_assistant::restore_registers() const noexcept
    {
      uint64_t fs_base;
      uint64_t gs_base;
      x86::gdtr_t gdtr = {};
      x86::idtr_t idtr = {};

      vmx::vmread(vmx::vmcs_fields::guest_fs_base, fs_base);
      x86::msr::write<x86::msr::fs_base>(fs_base);

      vmread(vmx::vmcs_fields::guest_gs_base, gs_base);
      x86::msr::write<x86::msr::gs_base>(gs_base);

      vmread(vmx::vmcs_fields::guest_gdtr_base, gdtr.base_address);
      vmread(vmx::vmcs_fields::guest_gdtr_limit, gdtr.limit);
      x86::write<x86::gdtr_t>(gdtr);

      vmread(vmx::vmcs_fields::guest_idtr_base, idtr.base_address);
      vmread(vmx::vmcs_fields::guest_idtr_limit, idtr.limit);
      x86::write<x86::idtr_t>(idtr);
    }

    void kernel_hook_assistant::handle_hlt(common::guest_regs* regs, vcpu* cpu_obj)
    {
      KdPrint(("hlt instruction executed.\n"));
    }

    void kernel_hook_assistant::handle_ept_misconfig(common::guest_regs* regs, vcpu* cpu_obj)
    {
      uint64_t guest_phys_address;
      vmx::vmread(vmx::vmcs_fields::guest_physical_address, guest_phys_address);

      KdPrint(("Fatal error. EPT Misconfiguration occured.\n"));
      KdPrint(("Physical address 0x%llx\n", guest_phys_address));
    }

    void kernel_hook_assistant::handle_vmcall(common::guest_regs* regs, vcpu* cpu_obj)
    {
      NTSTATUS vmcall_status = STATUS_SUCCESS;

      vmx::vmcall_number request_num = static_cast<vmx::vmcall_number>(regs->rcx & 0xFFFFFFFF);

      try
      {
        switch (request_num)
        {
          case vmx::vmcall_number::test:
          {
            KdPrint(("vmcall called with params 0x%llx, 0x%llx, 0x%llx\n", regs->rdx, regs->r8, regs->r9));

            break;
          }

          case vmx::vmcall_number::vmxoff:
          {
            execute_vmxoff_sequence(cpu_obj);

            break;
          }

          case vmx::vmcall_number::change_page_attrib:
          {
            hook::hook_context* context = reinterpret_cast<hook::hook_context*>(regs->rdx);
            globals::hook_builder->ept_hook(*context);

            break;
          }

          case vmx::vmcall_number::invept_all_contexts:
          {
            vmx::invept_all_contexts();

            break;
          }

          case vmx::vmcall_number::invept_single_context:
          {
            vmx::invept_single_context(regs->rdx);

            break;
          }

          case vmx::vmcall_number::unhook_all_pages:
          {
            globals::hook_builder->unhook_all_pages();

            break;
          }

          case vmx::vmcall_number::unhook_single_page:
          {
            globals::hook_builder->unhook_single_page(regs->rdx);

            break;
          }

          default:
          {
            KdPrint(("Unsupported vmcall number.\n"));
            vmcall_status = STATUS_UNSUCCESSFUL;

            break;
          }
        }

      }
      catch (std::exception& e)
      {
        DbgBreakPoint();
        KdPrint(("Exception in vmcall handler occured. %s\n", e.what()));
        vmcall_status = STATUS_UNSUCCESSFUL;
      }

      regs->rax = vmcall_status;
    }

    void kernel_hook_assistant::handle_monitor_trap_flag(common::guest_regs* regs, vcpu* cpu_obj)
    {
      if (*cpu_obj->mtf_restore_point())
      {
        ept::hooked_page_detail* page = *cpu_obj->mtf_restore_point();
        globals::pt_handler->set_pml1_and_invalidate_tlb(page->entry_address, page->changed_entry, vmx::invept_type::invept_single_context);
      }

      cpu_obj->set_monitor_trap_flag(false);
      cpu_obj->skip_instruction(false);
    }

    void kernel_hook_assistant::handle_ept_violation(common::guest_regs* regs, vcpu* cpu_obj)
    {
      const uint64_t guest_physical_address = cpu_obj->exit_guest_physical_address();
      const vmx::exit_qualification_t exit_qualification = cpu_obj->exit_qualification();
      ept::hooked_page_detail* hooked_page = globals::hook_builder->get_hooked_page_info(guest_physical_address);

      if (hooked_page == nullptr)
      {
        KdPrint(("Unexpected EPT violation.\n"));
        return;
      }

      globals::pt_handler->set_pml1_and_invalidate_tlb(hooked_page->entry_address,
        hooked_page->original_entry, vmx::invept_type::invept_single_context);

      uint64_t rip = cpu_obj->guest_rip();
      uint64_t exact_accessed_address = reinterpret_cast<uint64_t>(PAGE_ALIGN(hooked_page->virtual_address)) + guest_physical_address
        - reinterpret_cast<uint64_t>(PAGE_ALIGN(guest_physical_address));

      KdPrint(("Ept violation, RIP : 0x%llx, exact address : 0xllx\n", rip, exact_accessed_address));

      *cpu_obj->mtf_restore_point() = hooked_page;
      cpu_obj->set_monitor_trap_flag(true);
      cpu_obj->skip_instruction(false);
    }
  }
}
