#pragma once
#include <stdint.h>
#include <intrin.h>

extern "C"
{
  /* Common assembly procedures. */  

  uint16_t __read_cs() noexcept;
  void __write_cs(uint16_t cs) noexcept;
  uint16_t __read_ds() noexcept;
  void __write_ds(uint16_t ds) noexcept;

  uint16_t __read_es() noexcept;
  void __write_es(uint16_t es) noexcept;
  uint16_t __read_fs() noexcept;
  void __write_fs(uint16_t fs) noexcept;
  uint16_t __read_gs() noexcept;
  void __write_gs(uint16_t gs) noexcept;
  uint16_t __read_ss() noexcept;
  void __write_ss(uint16_t ss) noexcept;
  uint16_t __read_tr() noexcept;
  void __write_tr(uint16_t tr) noexcept;
  uint16_t __read_ldtr() noexcept;
  void __write_ldtr(uint16_t ldr) noexcept;

  void __read_gdt(void* gdt) noexcept;
  void __write_gdt(const void* gdt) noexcept;

  void __read_idt(void* idt) noexcept;
  void __write_idt(const void* idt) noexcept;

  uint32_t __read_ar(uint16_t selector) noexcept;
  uint32_t __read_sl(uint32_t segment) noexcept;

  uint64_t __read_rflags() noexcept;
  void __write_rflags(uint64_t) noexcept;

  uint64_t __read_dr(uint64_t index) noexcept;
  void __write_dr(uint64_t index, uint64_t value) noexcept;
}
