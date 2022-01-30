.code 

extern ?virtualize_current_system@vcpu@hh@@AEAAXPEAX@Z:proc

?save_state_and_start_virtualization@vcpu@hh@@AEAAXXZ proc frame

  pushfq
  .allocstack 8
  push rax
  .pushreg rax
  push rcx
  .pushreg rcx
  push rdx
  .pushreg rdx
  push rbx
  .pushreg rbx
  push rbp
  .pushreg rbp
  push rsi
  .pushreg rsi
  push rdi
  .pushreg rdi
  push r8
  .pushreg r9
  push r9
  .pushreg r9
  push r10
  .pushreg r10
  push r11
  .pushreg r11
  push r12
  .pushreg r12
  push r13
  .pushreg r13
  push r14
  .pushreg r14
  push r15
  .pushreg r15
  
  sub rsp, 0f8h
  .allocstack 0f8h
  .endprolog

  ; in thiscall first parameter is passed to rdx ( 'this' pointer is placed in rcx )

  mov rdx, rsp

  call ?virtualize_current_system@vcpu@hh@@AEAAXPEAX@Z

  int 3 ; we should never reach here as we execute vmlaunch in the above function.

  ; fall to restore_state
?save_state_and_start_virtualization@vcpu@hh@@AEAAXXZ endp

?restore_state@vcpu@hh@@CAXXZ proc

  add rsp, 0f8h
  pop r15
  pop r14
  pop r13
  pop r12
  pop r11
  pop r10
  pop r9
  pop r8
  pop rdi
  pop rsi
  pop rbp
  pop rbx
  pop rdx
  pop rcx
  pop rax
  
  popfq

  ret

?restore_state@vcpu@hh@@CAXXZ endp

end
