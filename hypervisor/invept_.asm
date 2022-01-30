.code

  VMX_ERROR_CODE_SUCCESS              = 0
  VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
  VMX_ERROR_CODE_FAILED               = 2

__invept proc

  invept rcx, oword ptr [rdx]
  jz @jz
  jc @jc
  xor rax, rax
  ret

  @jz:
  mov rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
  ret

  @jc:
  mov rax, VMX_ERROR_CODE_FAILED
  ret

__invept endp

end
