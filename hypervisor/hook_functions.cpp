#include "hooking.hpp"
#include "hypervisor.hpp"

namespace hh
{
  NTSTATUS NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) noexcept
  {
    std::wstring_view file_name = ObjectAttributes->ObjectName->Buffer;

    if (file_name.find(L"open_me") != std::wstring::npos)
    {
      return STATUS_ACCESS_DENIED;
    }

    return hook::pointers::NtCreateFileOrig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
      CreateDisposition, CreateOptions, EaBuffer, EaLength);
  }
}
