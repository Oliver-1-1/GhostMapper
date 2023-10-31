#pragma once
#include "ntDef.h"

#define CASE_SENSITIVE
typedef unsigned char CHAR8;
typedef unsigned short CHAR16;

typedef struct _IMAGE_IMPORT_DESCRIPTOR2 {
	UINT32   LookupTableRVA;             // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	UINT32   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	UINT32   ForwarderChain;                 // -1 if no forwarders
	UINT32   Name;
	UINT32   ImportAddressTable;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR2;

typedef IMAGE_IMPORT_DESCRIPTOR2* PIMAGE_IMPORT_DESCRIPTOR2;

typedef struct _IMAGE_IMPORT_DESCRIPTOR_OWN {
	UINT32   LookupTableRVA;             // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	UINT32   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	UINT32   ForwarderChain;                 // -1 if no forwarders
	UINT32   Name;
	UINT32   ImportAddressTable;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR_OWN;

typedef IMAGE_IMPORT_DESCRIPTOR_OWN* PIMAGE_IMPORT_DESCRIPTOR_OWN;
typedef struct _RELOC_NAME_TABLE_ENTRY
{
	UINT16 Hint;
	CHAR8 Name[];
} RELOC_NAME_TABLE_ENTRY, PRELOC_NAME_TABLE_ENTRY;

typedef struct _RELOC_BLOCK_HDR
{
	UINT32 PageRVA;
	UINT32 BlockSize;
} RELOC_BLOCK_HDR, * PRELOC_BLOCK_HDR;

typedef struct _RELOC_ENTRY
{
	UINT16 Offset : 12;
	UINT16 Type : 4;
} RELOC_ENTRY, * PRELOC_ENTRY;

namespace util {

	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		PVOID ExceptionTable;
		ULONG ExceptionTableSize;
		PVOID GpValue;
		PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT __Unused5;
		PVOID SectionPointer;
		ULONG CheckSum;
		PVOID LoadedImports;
		PVOID PatchInformation;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
	NTSTATUS Sleep(ULONGLONG milliseconds);
	HANDLE GetPidFromName(const unsigned short* t);
	HANDLE FindProcessByName(char* name, HANDLE ignoreId);
	PVOID GetModuleBase(LPCSTR moduleName);
	PIMAGE_NT_HEADERS GetHeader(PVOID module);;
	PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask);
	PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask);
	PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, LONG InstructionSize);
	VOID* GetModuleList();


	BOOLEAN WriteToProtectedMem(VOID* address, BYTE* source, ULONG length);
	BOOLEAN ZeroMemory(VOID* address, ULONG length);
	DWORD64 ResolveExport(PVOID imageBase, const char* functionName);
	VOID* GetLoadedModuleBase(const unsigned short* mod_name);
	VOID* FindExportByOrdinal(VOID* module, UINT16 ordinal);
	VOID* FindExport(VOID* module, const unsigned char* routine_name);
	UINT32* FindExportEntry(VOID* module, const CASE_SENSITIVE CHAR8* routine_name);
	UINT32* FindExportEntryByOrdinal(VOID* module, UINT16 ordinal);
}