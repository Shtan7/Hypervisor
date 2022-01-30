#define _USE_MATH_DEFINES 
#include "common.hpp"
#include <math.h>

namespace hh
{
  namespace common
  {
    double log2(double d) noexcept
    {
      return log(d) * M_LOG2E;
    }

    spinlock_guard::spinlock_guard(volatile long* lock) noexcept : lock_{ lock }
    {
      lock_spinlock();
    }

    spinlock_guard::~spinlock_guard() noexcept
    {
      unlock();
    }

    void spinlock_guard::lock_spinlock() noexcept
    {
      uint32_t wait = 1;

      while (!try_lock())
      {
        for (uint32_t j = 0; j < wait; j++)
        {
          _mm_pause();
        }

        if (wait * 2 > max_wait_)
        {
          wait = max_wait_;
        }
        else
        {
          wait *= 2;
        }
      }
    }

    bool spinlock_guard::try_lock() noexcept
    {
      return (!(*lock_) && !_interlockedbittestandset(lock_, 0));
    }

    void spinlock_guard::unlock() noexcept
    {
      *lock_ = 0;
    }

    uint64_t virtual_address_to_physical_address(void* virtual_address) noexcept
    {
      return MmGetPhysicalAddress(virtual_address).QuadPart;
    }

    uint64_t physical_address_to_virtual_address(uint64_t physical_address) noexcept
    {
      PHYSICAL_ADDRESS physical_addr{ .QuadPart = static_cast<long long>(physical_address) };

      return reinterpret_cast<uint64_t>(MmGetVirtualForPhysical(physical_addr));
    }

    void set_bit(void* address, uint64_t bit, bool set) noexcept
    {
      if (set)
      {
        BITMAP_ENTRY(bit, reinterpret_cast<uint32_t*>(address)) |= (1UL << BITMAP_SHIFT(bit));
      }
      else
      {
        BITMAP_ENTRY(bit, reinterpret_cast<uint32_t*>(address)) &= ~(1UL << BITMAP_SHIFT(bit));
      }
    }

    uint8_t get_bit(void* address, uint64_t bit) noexcept
    {
      uint64_t byte, k;

      byte = bit / 8;
      k = 7 - bit % 8;

      return reinterpret_cast<uint8_t*>(address)[byte] & (1 << k);
    }

    uint64_t find_system_directory_table_base() noexcept
    {
      // Return CR3 of the system process.
      nt_kprocess* system_process = reinterpret_cast<nt_kprocess*>(PsInitialSystemProcess);
      return system_process->directory_table_base;
    }

    irql_guard::irql_guard(KIRQL new_irql) noexcept : old_irql_{ KeGetCurrentIrql() }
    {
      KeLowerIrql(new_irql);
    }

    irql_guard::~irql_guard() noexcept
    {
      KeLowerIrql(old_irql_);
    }

    directory_base_guard::directory_base_guard(x86::cr3_t new_cr3) noexcept : old_cr3_{ x86::read<x86::cr3_t>() }
    {
      x86::write<x86::cr3_t>(new_cr3);
    }

    directory_base_guard::~directory_base_guard() noexcept
    {
      x86::write<x86::cr3_t>(old_cr3_);
    }
  }
}
