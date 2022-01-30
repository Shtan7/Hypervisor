#pragma once
#include <ntddk.h>
#include <map>
#include <limits>
#include <array>
#include "delete_constructors.hpp"
#include "common.hpp"

namespace hh
{
  class memory_manager abstract : non_relocatable
  {
  protected:
    volatile long spinlock_ = {};

  public:
    memory_manager() = default;
    virtual void* allocate(uint32_t allocation_size) = 0;
    virtual void* allocate_align(uint32_t allocation_size, std::align_val_t align) = 0;
    virtual void deallocate(void* ptr_to_allocation) = 0;
    virtual ~memory_manager() = default;
  };

  // Simple allocator that uses buddy allocation algorithm.
  class buddy_allocator : public memory_manager
  {
  private:
    struct node
    {
      node* next;
    };

    struct header
    {
      uint64_t size;
    };

  private:
    std::map<uint64_t, uint64_t> aligned_allocations_;
    std::size_t size_;
    void* start_address_;
    static constexpr uint64_t c_log2_header = common::compile_time_log2(sizeof(header));
    std::array<node*, std::numeric_limits<uint64_t>::digits - c_log2_header> buckets_ = {};
    volatile long map_lock_ = {};

  private:
    void init() noexcept;

  public:
    static constexpr uint32_t c_total_number_of_pages = 0x1E06;

  public:
    void* allocate(uint32_t allocation_size) override;
    void deallocate(void* ptr_to_allocation) override;
    void deallocate_internal(void* ptr_to_allocation);
    void* allocate_align(uint32_t allocation_size, std::align_val_t align) override;
    buddy_allocator(uint32_t size);
    virtual ~buddy_allocator();
  };
}
