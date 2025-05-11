#pragma once
#include "nt.hpp"
#include "dump.hpp" 
#define PAGE_MASK  0xFFF
#define SIZE_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + (((Size) & PAGE_MASK) ? 1 : 0))
#define PAGES_TO_SIZE(Pages) ((Pages) << PAGE_SIZE)

NTSTATUS GetSystemModuleInformation(LPCSTR name, PRTL_PROCESS_MODULE_INFORMATION module);
NTSTATUS MapGhostDriver(LPCSTR name);
NTSTATUS PatchMemory(RTL_PROCESS_MODULE_INFORMATION module);
UINT64 ZGetProcAddress(UINT64 base, PCSTR export_name);
NTSTATUS WriteToProtectedMemory(PVOID address, PUCHAR source, ULONG length);
NTSTATUS ZeroMemory(PVOID address, ULONG length);
PPte GetPte(UINT64 addr);
