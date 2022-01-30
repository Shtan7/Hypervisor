.code

__read_cs proc

  mov ax, cs
  ret

__read_cs endp

__write_cs proc

  mov cs, cx
  ret

__write_cs endp

__read_ds proc

  mov ax, cs
  ret

__read_ds endp

__write_ds proc

  mov ds, cx
  ret

__write_ds endp

__read_es proc

  mov ax, es
  ret

__read_es endp

__write_es proc

  mov es, cx
  ret

__write_es endp

__read_fs proc

  mov ax, fs
  ret

__read_fs endp

__write_fs proc

  mov fs, cx
  ret

__write_fs endp

__read_gs proc

  mov ax, gs
  ret

__read_gs endp

__write_gs proc

  mov gs, cx
  ret

__write_gs endp

__read_ss proc

  mov ax, ss
  ret

__read_ss endp

__write_ss proc

  mov ss, cx
  ret

__write_ss endp

__read_tr proc

  str ax
  ret

__read_tr endp

__write_tr proc

  ltr cx
  ret

__write_tr endp

__read_ldtr proc

  sldt ax
  ret

__read_ldtr endp

__write_ldtr proc

  lldt cx
  ret

__write_ldtr endp

__read_gdt proc

  sgdt fword ptr [rcx]
  ret

__read_gdt endp

__write_gdt proc

  lgdt fword ptr [rcx]
  ret

__write_gdt endp

__read_idt proc

  sidt fword ptr [rcx]
  ret

__read_idt endp

__write_idt proc

  lidt fword ptr [rcx]
  ret

__write_idt endp

__read_ar proc

  lar rax, rcx
  ret

__read_ar endp

__read_sl proc

  lsl eax, ecx
  ret

__read_sl endp

__read_rflags proc

  pushfq
  pop rax
  ret

__read_rflags endp

__write_rflags proc

  push rcx
  popfq
  ret

__write_rflags endp

__read_dr proc

  cmp rcx, 0
  je dr0_l
  cmp rcx, 1
  je dr1_l
  cmp rcx, 2
  je dr2_l
  cmp rcx, 6
  je dr6_l
  cmp rcx, 7
  je dr7_l
  jmp bad_register

  dr0_l:
  mov rax, dr0
  ret
  dr1_l:
  mov rax, dr1
  ret
  dr2_l:
  mov rax, dr2
  ret
  dr3_l:
  mov rax, dr3
  ret
  dr6_l:
  mov rax, dr6
  ret
  dr7_l:
  mov rax, dr7
  ret

  bad_register:

  mov eax, 0DEADBEAFh
  ret

__read_dr endp


__write_dr proc

  cmp rcx, 0
  je dr0_l
  cmp rcx, 1
  je dr1_l
  cmp rcx, 2
  je dr2_l
  cmp rcx, 6
  je dr6_l
  cmp rcx, 7
  je dr7_l
  jmp bad_register
 

  dr0_l:
  mov dr0, rdx
  ret
  dr1_l:
  mov dr1, rdx
  ret
  dr2_l:
  mov dr2, rdx
  ret
  dr3_l:
  mov dr3, rdx
  ret
  dr6_l:
  mov dr6, rdx
  ret
  dr7_l:
  mov dr7, rdx
  ret

  bad_register:

  mov eax, 0DEADBEAFh
  ret

__write_dr endp

end
