.code

  VMX_ERROR_CODE_SUCCESS              = 0
  VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
  VMX_ERROR_CODE_FAILED               = 2

__invvpid proc

  invvpid rcx, oword ptr [rdx]
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

__invvpid endp

end
