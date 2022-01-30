#pragma once

struct non_copyable
{
  non_copyable() = default;
  non_copyable(const non_copyable&) = delete;
  non_copyable& operator=(const non_copyable&) = delete;
  non_copyable(non_copyable&&) = default;
  non_copyable& operator=(non_copyable&&) = default;
  ~non_copyable() = default;
};

struct non_relocatable
{
  non_relocatable() = default;
  non_relocatable(const non_relocatable&) = delete;
  non_relocatable& operator=(const non_relocatable&) = delete;
  non_relocatable(non_relocatable&&) = delete;
  non_relocatable& operator=(non_relocatable&&) = delete;
  ~non_relocatable() = default;
};
