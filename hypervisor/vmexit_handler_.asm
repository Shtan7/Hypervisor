.data

local_var_offset = 12h ; mem cell for vmxoff handler

.code

extern ?handlers_dispatcher@vmexit_handler@hv_event_handlers@hh@@CA_NPEAUguest_regs@common@3@@Z:proc
extern ?vm_resume@vmexit_handler@hv_event_handlers@hh@@CAXXZ:proc
extern ?get_stack_pointer_for_vmxoff@vmexit_handler@hv_event_handlers@hh@@CA_KXZ:proc
extern ?get_instruction_pointer_for_vmxoff@vmexit_handler@hv_event_handlers@hh@@CA_KXZ:proc

?vmexit_entry@vmexit_handler@hv_event_handlers@hh@@CAXXZ proc

  push 0 ; for return address in vmxoff handler

  pushfq
  push r15
  push r14
  push r13
  push r12
  push r11
  push r10
  push r9
  push r8        
  push rdi
  push rsi
  push rbp
  push rbp ; rsp
  push rbx
  push rdx
  push rcx
  push rax
  push rax ; fxsave area

  mov rcx, rsp  ; Ptr to guest regs
  sub rsp, 28h 
  call ?handlers_dispatcher@vmexit_handler@hv_event_handlers@hh@@CA_NPEAUguest_regs@common@3@@Z
  add rsp, 28h

  cmp al, 1
  je ?vmxoff_handler@vmexit_handler@hv_event_handlers@hh@@CAXXZ

  restore_state:
  pop rax ; fxsave area
  pop rax
  pop rcx
  pop rdx
  pop rbx
  pop rbp ; rsp
  pop rbp
  pop rsi
  pop rdi 
  pop r8
  pop r9
  pop r10
  pop r11
  pop r12
  pop r13
  pop r14
  pop r15
  popfq

  sub rsp, 100h
  jmp ?vm_resume@vmexit_handler@hv_event_handlers@hh@@CAXXZ

?vmexit_entry@vmexit_handler@hv_event_handlers@hh@@CAXXZ endp

?vmxoff_handler@vmexit_handler@hv_event_handlers@hh@@CAXXZ proc

  sub rsp, 20h
  call ?get_stack_pointer_for_vmxoff@vmexit_handler@hv_event_handlers@hh@@CA_KXZ
  add rsp, 20h

  mov qword ptr [rsp+local_var_offset*8], rax ; put guest stack pointer on stack

  sub rsp, 20h
  call ?get_instruction_pointer_for_vmxoff@vmexit_handler@hv_event_handlers@hh@@CA_KXZ
  add rsp, 20h

  mov rdx, rsp ; save current stack pointer

  mov rbx, qword ptr [rsp+local_var_offset*8] ; get guest stack pointer

  mov rsp, rbx ; set up guest stack as current

  push rax ; push return address to new stack

  mov rsp, rdx ; restore old stack

  sub rbx, 8 ; sub rsp because we pushed return address on stack

  mov qword ptr [rsp+local_var_offset*8], rbx ; save guest stack address

  restore_state:
  pop rax ; fxsave area
  pop rax
  pop rcx
  pop rdx
  pop rbx
  pop rbp ; rsp
  pop rbp
  pop rsi
  pop rdi 
  pop r8
  pop r9
  pop r10
  pop r11
  pop r12
  pop r13
  pop r14
  pop r15
  popfq

  pop rsp ; setup guest stack address
  ret ; return to place where vmxoff vmcall was called

?vmxoff_handler@vmexit_handler@hv_event_handlers@hh@@CAXXZ endp

end
