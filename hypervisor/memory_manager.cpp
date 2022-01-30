#include "memory_manager.hpp"
#include "common.hpp"
#include "globals.hpp"

namespace hh
{
  buddy_allocator::buddy_allocator(uint32_t size) : size_{ size }
  {
    start_address_ = ExAllocatePoolWithTag(NonPagedPool, size, common::pool_tag);

    if (start_address_ == nullptr)
    {
      throw std::exception{ "Failed to allocate start buffer for allocator." };
    }

    init();
  }
  
  void buddy_allocator::init() noexcept
  {
    node* root = reinterpret_cast<node*>(start_address_);
    root->next = nullptr;
    const uint64_t bucket = (uint64_t)ceil(common::log2(size_)) - 1 - c_log2_header;
    buckets_[bucket] = root;
  }

  buddy_allocator::~buddy_allocator()
  {
    ExFreePoolWithTag(start_address_, common::pool_tag);
    start_address_ = nullptr;
  }

  void* buddy_allocator::allocate(uint32_t size)
  {
    const common::spinlock_guard _{ &spinlock_ };

    int bucket = max(int(ceil(common::log2(size + sizeof(header))) - 1 - c_log2_header), 0);

    if (buckets_[bucket] != nullptr)
    {
      node* node_ = buckets_[bucket];
      buckets_[bucket] = node_->next;

      header* header_ = reinterpret_cast<header*>(node_);
      header_->size = (uint64_t)pow(2, bucket + 1 + c_log2_header) | 1;
      void* address = reinterpret_cast<char*>(node_) + sizeof(header);

      return address;
    }

    int j;

    for (j = bucket + 1; j < buckets_.size(); j++)
    {
      if (buckets_[j] != nullptr)
      {
        break;
      }
    }

    if (j == buckets_.size())
    {
      throw std::bad_alloc{};
    }

    node* temp = buckets_[j];
    buckets_[j] = temp->next;

    j--;

    for (; j >= bucket; j--)
    {
      node* node_ = reinterpret_cast<node*>(reinterpret_cast<char*>(temp) + (uint64_t)pow(2, j + 1 + c_log2_header));
      node_->next = buckets_[j];
      buckets_[j] = node_;
    }

    header* header_ = reinterpret_cast<header*>(temp);
    header_->size = (uint64_t)pow(2, j + 2 + c_log2_header) | 1;
    void* address = reinterpret_cast<char*>(temp) + sizeof(header);

    return address;
  }

  void buddy_allocator::deallocate(void* ptr_to_allocation)
  {
    decltype(aligned_allocations_.extract(0)) map_node = {};

    {
      const common::spinlock_guard _{ &map_lock_ };
      if (aligned_allocations_.contains(reinterpret_cast<uint64_t>(ptr_to_allocation)))
      {
        uint64_t address = reinterpret_cast<uint64_t>(ptr_to_allocation);
        map_node = aligned_allocations_.extract(address);
      }
    }

    {
      const common::spinlock_guard _{ &spinlock_ };

      if (!map_node.empty())
      {
        void* ptr = reinterpret_cast<void*>(map_node.mapped());
        deallocate_internal(ptr);

        return;
      }

      deallocate_internal(ptr_to_allocation);
    }

    if (!map_node.empty())
    {
      map_node.~_Node_handle();
    }
  }

  void buddy_allocator::deallocate_internal(void* ptr_to_allocation)
  {
    header* header_ = reinterpret_cast<header*>(reinterpret_cast<char*>(ptr_to_allocation) - sizeof(header));

    const uint64_t size = header_->size & ~(uint64_t)1;
    const uint64_t bucket = (uint64_t)common::log2(size) - 1 - c_log2_header;

    node* node_ = reinterpret_cast<node*>(header_);

    uint64_t buddy_number = (reinterpret_cast<char*>(header_) - static_cast<char*>(start_address_)) / size;
    char* buddy_address;

    if (buddy_number % 2 == 0)
    {
      buddy_address = reinterpret_cast<char*>(header_) + size;
    }
    else
    {
      buddy_address = reinterpret_cast<char*>(header_) - size;
    }

    if (buddy_address == (static_cast<char*>(start_address_) + size_) || *reinterpret_cast<uint64_t*>(buddy_address) & 1)
    {
      node_->next = buckets_[bucket];
      buckets_[bucket] = node_;
    }
    else
    {
      node* prev_buddy = nullptr;
      node* buddy = reinterpret_cast<node*>(buddy_address);
      node* context = buckets_[bucket];

      while (context != buddy && context != nullptr)
      {
        prev_buddy = context;
        context = context->next;
      }

      if (context == nullptr)
      {
        node_->next = buckets_[bucket];
        buckets_[bucket] = node_;
      }
      else
      {
        if (prev_buddy == nullptr)
        {
          buckets_[bucket] = buddy->next;
        }
        else
        {
          prev_buddy->next = buddy->next;
        }

        if (buddy_number % 2 == 0)
        {
          node_->next = buckets_[bucket + 1];
          buckets_[bucket + 1] = node_;
        }
        else
        {
          buddy->next = buckets_[bucket + 1];
          buckets_[bucket + 1] = buddy;
        }
      }
    }
  }

  void* buddy_allocator::allocate_align(uint32_t allocation_size, std::align_val_t align)
  {
    uint64_t aligned_memory = reinterpret_cast<uint64_t>(allocate(allocation_size * 2));
    uint64_t aligned_address = (aligned_memory + static_cast<uint64_t>(align) - 1ull) & ~(static_cast<uint64_t>(align) - 1ull);

    {
      common::spinlock_guard _{ &map_lock_ };
      aligned_allocations_.insert({ aligned_address, aligned_memory });
    }

    return reinterpret_cast<void*>(aligned_address);
  }
}
