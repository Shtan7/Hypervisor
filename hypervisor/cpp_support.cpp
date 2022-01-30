#include <ntifs.h>
#include <exception>
#include "memory_manager.hpp"
#include "globals.hpp"
#include "common.hpp"

using namespace hh;

using _PVFV = void(__cdecl*)(void); // PVFV = Pointer to Void Func(Void)
using _PIFV = int(__cdecl*)(void); // PIFV = Pointer to Int Func(Void)
using _PVFVP = void(__cdecl*)(void*); // PVFVP = Pointer to Void Func(Void*)

constexpr int max_destructors_count = 64;
static _PVFV onexitarray[max_destructors_count] = {};
static _PVFV* onexitbegin = nullptr, * onexitend = nullptr;

// C initializers:
#pragma section(".CRT$XIA", long, read)
__declspec(allocate(".CRT$XIA")) _PIFV __xi_a[] = { 0 };
#pragma section(".CRT$XIZ", long, read)
__declspec(allocate(".CRT$XIZ")) _PIFV __xi_z[] = { 0 };

// C++ initializers:
#pragma section(".CRT$XCA", long, read)
__declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = { 0 };
#pragma section(".CRT$XCZ", long, read)
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = { 0 };

// C pre-terminators:
#pragma section(".CRT$XPA", long, read)
__declspec(allocate(".CRT$XPA")) _PVFV __xp_a[] = { 0 };
#pragma section(".CRT$XPZ", long, read)
__declspec(allocate(".CRT$XPZ")) _PVFV __xp_z[] = { 0 };

// C terminators:
#pragma section(".CRT$XTA", long, read)
__declspec(allocate(".CRT$XTA")) _PVFV __xt_a[] = { 0 };
#pragma section(".CRT$XTZ", long, read)
__declspec(allocate(".CRT$XTZ")) _PVFV __xt_z[] = { 0 };

#pragma data_seg()

#pragma comment(linker, "/merge:.CRT=.rdata")

// Already defined in kernel math library.
// extern "C" int _fltused = 0;

extern "C" void __std_terminate()
{
  KeBugCheck(KMODE_EXCEPTION_NOT_HANDLED);
}

extern "C" int __cdecl __init_on_exit_array()
{
  onexitend = onexitbegin = onexitarray;
  *onexitbegin = 0;
  return 0;
}

extern "C" int __cdecl atexit(_PVFV fn)
{
  // ToDo: replace with dynamically allocated list of destructors!
  if (onexitend > &onexitarray[max_destructors_count - 1])
    return 1; // Not enough space
  *onexitend = fn;
  onexitend++;
  return 0;
}

int __cdecl _purecall()
{
  // It's abnormal execution, so we should detect it:
  __int2c();
  return 0;
}

static void execute_pvfv_array(_PVFV* begin, _PVFV* end)
{
  _PVFV* fn = begin;
  while (fn != end)
  {
    if (*fn) (**fn)();
    ++fn;
  }
}

static int execute_pifv_array(_PIFV* begin, _PIFV* end)
{
  _PIFV* fn = begin;
  while (fn != end)
  {
    if (*fn)
    {
      int result = (**begin)();
      if (result) return result;
    }
    ++fn;
  }
  return 0;
}

extern "C" int __crt_init()
{
  __init_on_exit_array();
  int result = execute_pifv_array(__xi_a, __xi_z);
  if (result) return result;
  execute_pvfv_array(__xc_a, __xc_z);
  return 0;
}

extern "C" void __crt_deinit()
{
  if (onexitbegin)
  {
    while (--onexitend >= onexitbegin)
    {
      if (*onexitend != 0)(**onexitend)();
    }
  }
  execute_pvfv_array(__xp_a, __xp_z);
  execute_pvfv_array(__xt_a, __xt_z);
}

void __cdecl destroy_array_in_reversed_order(void* arr_begin, size_t element_size,
  size_t count, _PVFVP destructor) 
{
  auto* current_obj{ static_cast<uint8_t*>(arr_begin) + element_size * count };

  while (count-- > 0) 
  {
    current_obj -= element_size;
    destructor(current_obj);
  }
}

void __cdecl construct_array(void* arr_begin, size_t element_size,
  size_t count, _PVFVP constructor, _PVFVP destructor) 
{
  auto* current_obj{static_cast<uint8_t*>(arr_begin)};
  size_t idx{ 0 };

  try 
  {
    for (; idx < count; ++idx) 
    {
      constructor(current_obj);
      current_obj += element_size;
    }
  } 
  catch (...) 
  {
    destroy_array_in_reversed_order(arr_begin, element_size, idx, destructor);
    throw;
  }
}

EXTERN_C void __cdecl __ehvec_ctor(void* arr_begin, size_t element_size,
  size_t count, _PVFVP constructor, _PVFVP destructor) 
{
  construct_array(arr_begin, element_size, count, constructor, destructor);
}

EXTERN_C void __cdecl __ehvec_dtor(void* arr_end, size_t element_size,
  size_t count, _PVFVP destructor) 
{
  destroy_array_in_reversed_order(arr_end, element_size, count, destructor);
}

void* __cdecl operator new(size_t size)
{
  void* pointer;

  if (globals::mem_manager != nullptr)
  {
    pointer = globals::mem_manager->allocate(size);
  }
  else
  {
    pointer = ExAllocatePoolWithTag(NonPagedPool, size, common::pool_tag);
  }

  if (pointer) RtlZeroMemory(pointer, size);
  return pointer;
}

void* __cdecl operator new(size_t size, std::align_val_t align)
{
  void* pointer;

  if (globals::mem_manager != nullptr)
  {
    pointer = globals::mem_manager->allocate_align(size, align);
  }
  else
  {
    pointer = ExAllocatePoolWithTag(NonPagedPool, size, common::pool_tag);
  }

  if (pointer) RtlZeroMemory(pointer, size);
  return pointer;
}

void* __cdecl operator new[](size_t size)
{
  void* pointer;

  if (globals::mem_manager != nullptr)
  {
    pointer = globals::mem_manager->allocate(size);
  }
  else
  {
    pointer = ExAllocatePoolWithTag(NonPagedPool, size, common::pool_tag);
  }

  if (pointer) RtlZeroMemory(pointer, size);
  return pointer;
}

void* __cdecl operator new[](size_t size, std::align_val_t align)
{
  void* pointer;

  if (globals::mem_manager != nullptr)
  {
    pointer = globals::mem_manager->allocate_align(size, align);
  }
  else
  {
    pointer = ExAllocatePoolWithTag(NonPagedPool, size, common::pool_tag);
  }

  if (pointer) RtlZeroMemory(pointer, size);
  return pointer;
}

void __cdecl operator delete(void* pointer)
{
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

void __cdecl operator delete(void* pointer, std::align_val_t align)
{
  UNREFERENCED_PARAMETER(align);
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

void __cdecl operator delete(void* pointer, size_t size)
{
  UNREFERENCED_PARAMETER(size);
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

void __cdecl operator delete(void* pointer, size_t size, std::align_val_t align)
{
  UNREFERENCED_PARAMETER(size);
  UNREFERENCED_PARAMETER(align);
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

void __cdecl operator delete[](void* pointer)
{
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

void __cdecl operator delete[](void* pointer, std::align_val_t align)
{
  UNREFERENCED_PARAMETER(align);
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

void __cdecl operator delete[](void* pointer, size_t size)
{
  UNREFERENCED_PARAMETER(size);
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

void __cdecl operator delete[](void* pointer, size_t size, std::align_val_t align)
{
  UNREFERENCED_PARAMETER(size);
  UNREFERENCED_PARAMETER(align);
  if (globals::mem_manager != nullptr)
  {
    globals::mem_manager->deallocate(pointer);
  }
  else
  {
    ExFreePoolWithTag(pointer, common::pool_tag);
  }
}

[[noreturn]]
static void RaiseException(ULONG BugCheckCode)
{
  KdBreakPoint();
  KeBugCheck(BugCheckCode);
}

[[noreturn]]
void __cdecl _invalid_parameter_noinfo_noreturn()
{
  RaiseException(DRIVER_INVALID_CRUNTIME_PARAMETER);
}

namespace std
{
  [[noreturn]]
  void __cdecl _Xbad_alloc()
  {
    RaiseException(INSTALL_MORE_MEMORY);
  }

  [[noreturn]]
  void __cdecl _Xinvalid_argument(_In_z_ const char*)
  {
    RaiseException(DRIVER_INVALID_CRUNTIME_PARAMETER);
  }

  [[noreturn]]
  void __cdecl _Xlength_error(_In_z_ const char*)
  {
    RaiseException(KMODE_EXCEPTION_NOT_HANDLED);
  }

  [[noreturn]]
  void __cdecl _Xout_of_range(_In_z_ const char*)
  {
    RaiseException(DRIVER_OVERRAN_STACK_BUFFER);
  }

  [[noreturn]]
  void __cdecl _Xoverflow_error(_In_z_ const char*)
  {
    RaiseException(DRIVER_OVERRAN_STACK_BUFFER);
  }

  [[noreturn]]
  void __cdecl _Xruntime_error(_In_z_ const char*)
  {
    RaiseException(KMODE_EXCEPTION_NOT_HANDLED);
  }

  [[noreturn]]
  void __cdecl RaiseHandler(const std::exception&)
  {
    RaiseException(KMODE_EXCEPTION_NOT_HANDLED);
  }

  _Prhand _Raise_handler = &RaiseHandler;
}

[[noreturn]]
void __cdecl _invoke_watson(
  wchar_t const* const expression,
  wchar_t const* const function_name,
  wchar_t const* const file_name,
  unsigned int   const line_number,
  uintptr_t      const reserved)
{
  UNREFERENCED_PARAMETER(expression);
  UNREFERENCED_PARAMETER(function_name);
  UNREFERENCED_PARAMETER(file_name);
  UNREFERENCED_PARAMETER(line_number);
  UNREFERENCED_PARAMETER(reserved);

  KdBreakPoint();
  RaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

// For <unordered_set> and <unordered_map> support:
#ifdef _AMD64_
#pragma function(ceilf)
_Check_return_ float __cdecl ceilf(_In_ float _X)
{
  int v = static_cast<int>(_X);
  return static_cast<float>(_X > static_cast<float>(v) ? v + 1 : v);
}
#else
#pragma function(ceil)
_Check_return_ double __cdecl ceil(_In_ double _X)
{
  int v = static_cast<int>(_X);
  return static_cast<double>(_X > static_cast<double>(v) ? v + 1 : v);
}
#endif
