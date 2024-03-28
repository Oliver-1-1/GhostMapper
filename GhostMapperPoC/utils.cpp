#include "utils.h"
//All copy paste, maby one or two i have written.
NTSTATUS util::Sleep(ULONGLONG milliseconds)
{
	LARGE_INTEGER delay;
	ULONG* split;

	milliseconds *= 1000000;

	milliseconds /= 100;

	milliseconds = -milliseconds;

	split = (ULONG*)&milliseconds;

	delay.LowPart = *split;

	split++;

	delay.HighPart = *split;


	KeDelayExecutionThread(KernelMode, 0, &delay);

	return STATUS_SUCCESS;
}

HANDLE util::GetPidFromName(const unsigned short* t) {

	NTSTATUS status = STATUS_SUCCESS;
	ULONG bufferSize = 0;
	PVOID buffer = NULL;

	PSYSTEM_PROCESS_INFORMATION pCurrent = NULL;

	UNICODE_STRING processName;
	RtlInitUnicodeString(&processName, t);

	status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, buffer, bufferSize, &bufferSize);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'MDMP');
		if (buffer == NULL) {
			return pCurrent;
		}
		else {
			status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
			if (!NT_SUCCESS(status)) {
				ExFreePoolWithTag(buffer, 'MDMP');
				return pCurrent;
			}
		}
	}

	pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (pCurrent) {
		if (pCurrent->ImageName.Buffer != NULL) {
			if (RtlCompareUnicodeString(&(pCurrent->ImageName), &processName, TRUE) == 0) {
				ExFreePoolWithTag(buffer, 'MDMP');
				return pCurrent->ProcessId;
			}
		}
		if (pCurrent->NextEntryOffset == 0) {
			pCurrent = NULL;
		}
		else {
			pCurrent = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pCurrent) + pCurrent->NextEntryOffset);
		}
	}



	return pCurrent;
}

PVOID util::GetModuleBase(LPCSTR moduleName) {
	PVOID moduleBase = NULL;
	ULONG info = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);

	if (!info) {
		return moduleBase;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, info, 'HELL');
	status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);
	if (!NT_SUCCESS(status)) {
		return moduleBase;
	}
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	if (modules->NumberOfModules > 0) {
		if (!moduleName) {
			moduleBase = modules->Modules[0].ImageBase;
		}
		else {
			for (auto i = 0; i < modules->NumberOfModules; i++) {
				if (!strcmp((CHAR*)module[i].FullPathName, moduleName)) {
					moduleBase = module[i].ImageBase;
				}
			}
		}
	}

	if (modules) {
		ExFreePoolWithTag(modules, 'HELL');
	}

	return moduleBase;
}

PIMAGE_NT_HEADERS util::GetHeader(PVOID module) {
	return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
}

PBYTE util::FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {
	auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
	{
		for (auto x = buffer; *mask; pattern++, mask++, x++) {
			auto addr = *(BYTE*)(pattern);
			if (addr != *x && *mask != '?')
				return FALSE;
		}

		return TRUE;
	};

	for (auto x = 0; x < size - strlen(mask); x++) {

		auto addr = (PBYTE)module + x;
		if (checkMask(addr, pattern, mask))
			return addr;
	}

	return NULL;
}

PBYTE util::FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask) {
	auto header = GetHeader(base);
	auto section = IMAGE_FIRST_SECTION(header);
	for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {
		if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4) || !memcmp(section->Name, "PROTDATA", 8)) {
			auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (addr) {
				//
				(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Found in Section -> [ %s ]", section->Name);
				return addr;
			}
		}
	}

	return NULL;
}

PVOID util::ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, LONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

VOID* util::GetModuleList() {
	ULONG length = 0;
	ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, 0, 0, &length);
	length += (10 * 1024);

	VOID* module_list = ExAllocatePool((POOL_TYPE)(POOL_COLD_ALLOCATION | PagedPool), length);
	NTSTATUS status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, module_list, length, &length);

	if (status){
		if (module_list) ExFreePool(module_list);
		return 0;
	}

	if (!module_list){
		return 0;
	}

	return module_list;
}


BOOLEAN util::WriteToProtectedMem(VOID* address, BYTE* source, ULONG length) {
	MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
	if (!mdl) return FALSE;


	MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (!map_address) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (status) {
		MmUnmapLockedPages(map_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	RtlCopyMemory(map_address, source, length);
	MmUnmapLockedPages(map_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}

BOOLEAN util::ZeroMemory(VOID* address, ULONG length)
{
	MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
	if (!mdl) {
		return FALSE;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (!map_address) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (status) {
		MmUnmapLockedPages(map_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}
	RtlZeroMemory(map_address, length);

	MmUnmapLockedPages(map_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}


static __forceinline int CustomCompare(const char* a, const char* b)
{
	while (*a && *a == *b) { ++a; ++b; }
	return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}


static UINT64 ascii_to_int(CHAR8* ascii)
{
	UINT64 return_int = 0;
	while (*ascii)
	{
		if (*ascii <= '0' || *ascii >= '9')
			return 0;
		return_int *= 10;
		return_int += *ascii - '0';
		ascii++;
	}
	return return_int;
}
static void Copy_Memory(const VOID* Dest, const VOID* Src, unsigned long long Len) // CopyMem relies on boot services
{
	for (int i = 0; i < Len; ++i)
	{
		((UINT8*)Dest)[i] = ((UINT8*)Src)[i];
	}
}
CHAR16 wc_to_lower(CHAR16 c)
{
	if (c >= 'A' && c <= 'Z')
		return c += ('a' - 'A');
	else return c;
}
__int64 u_wcsnicmp(const CHAR16* First, const CHAR16* Second, unsigned long long Length)
{
	for (int i = 0; i < Length && First[i] && Second[i]; ++i) // Channeling my inner Python developer
		if (wc_to_lower(First[i]) != wc_to_lower(Second[i]))
			return First[i] - Second[i];

	return 0;
}


UINT32* util::FindExportEntryByOrdinal(VOID* module, UINT16 ordinal){
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	if (dos->e_magic != 0x5A4D)
		return NULL;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS)((UINT8*)module + dos->e_lfanew);
	UINT32 exports_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress; // This corresponds to export directory
	if (!exports_rva)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)module + exports_rva);
	UINT16 index = ordinal - (UINT16)export_dir->Base;

	UINT32* export_func_table = (UINT32*)((UINT8*)module + export_dir->AddressOfFunctions);
	if (export_func_table[index] < nt->OptionalHeader.DataDirectory[0].VirtualAddress ||
		export_func_table[index] > nt->OptionalHeader.DataDirectory[0].VirtualAddress + nt->OptionalHeader.DataDirectory[0].Size)
		return export_func_table + index;
	// Handle the case of a forwarder export entry
	else
	{
		CHAR16 buffer[260];
		CHAR8* forwarder_rva_string = (CHAR8*)module + export_func_table[index];
		UINT16 dll_name_length;
		for (dll_name_length = 0; dll_name_length < 259; ++dll_name_length)
			if (forwarder_rva_string[dll_name_length] == '.') break;
		for (int i = 0; i < dll_name_length; ++i)
			buffer[i] = (CHAR16)forwarder_rva_string[i];
		buffer[dll_name_length] = L'\0';
		if (forwarder_rva_string[dll_name_length + 1] == '#')
			return FindExportEntryByOrdinal(util::GetLoadedModuleBase(buffer), (UINT16)ascii_to_int(&forwarder_rva_string[dll_name_length + 2]));
		else
			return FindExportEntry(util::GetLoadedModuleBase(buffer), forwarder_rva_string + dll_name_length + 1);
	}
}


UINT32* util::FindExportEntry(VOID* module, const CASE_SENSITIVE CHAR8* routine_name){
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	if (dos->e_magic != 0x5A4D)
		return NULL;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS)((UINT8*)module + dos->e_lfanew);
	UINT32 exports_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress; // This corresponds to export directory
	if (!exports_rva)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)module + exports_rva);
	UINT32* name_table = (UINT32*)((UINT8*)module + export_dir->AddressOfNames);

	// Binary Search
	for (int lower = 0, upper = export_dir->NumberOfNames - 1; upper >= lower;)
	{
		int i = (upper + lower) / 2;
		const CHAR8* func_name = (CHAR8*)((UINT8*)module + name_table[i]);
		__int64 diff = strcmp((const char*)routine_name, (const char*)func_name);
		if (diff > 0)
			lower = i + 1;
		else if (diff < 0)
			upper = i - 1;
		else
		{
			UINT32* export_func_table = (UINT32*)((UINT8*)module + export_dir->AddressOfFunctions);
			UINT16* ordinal_table = (UINT16*)((UINT8*)module + export_dir->AddressOfNameOrdinals);

			UINT16 index = ordinal_table[i];
			if (export_func_table[index] < nt->OptionalHeader.DataDirectory[0].VirtualAddress ||
				export_func_table[index] > nt->OptionalHeader.DataDirectory[0].VirtualAddress + nt->OptionalHeader.DataDirectory[0].Size)
				return export_func_table + index;
			// Handle the case of a forwarder export entry
			else
			{
				CHAR16 buffer[260];
				CHAR8* forwarder_rva_string = (CHAR8*)module + export_func_table[index];
				UINT16 dll_name_length;
				for (dll_name_length = 0; dll_name_length < 259; ++dll_name_length)
					if (forwarder_rva_string[dll_name_length] == '.') break;
				for (int j = 0; j < dll_name_length; ++j)
					buffer[j] = (CHAR16)forwarder_rva_string[j];
				buffer[dll_name_length] = L'\0';
				if (forwarder_rva_string[dll_name_length + 1] == '#')
					return FindExportEntryByOrdinal(util::GetLoadedModuleBase(buffer), (UINT16)ascii_to_int(&forwarder_rva_string[dll_name_length + 2]));
				else
					return FindExportEntry(util::GetLoadedModuleBase(buffer), forwarder_rva_string + dll_name_length + 1);
			}
		}
	}
	return NULL;
}

VOID* util::FindExport(VOID* module, const unsigned char* routine_name)
{
	UINT32* entry = FindExportEntry(module, routine_name);
	if (!entry)
		return NULL;
	return (VOID*)((UINT8*)module + *entry);
}


VOID* util::FindExportByOrdinal(VOID* module, UINT16 ordinal)
{
	UINT32* entry = FindExportEntryByOrdinal(module, ordinal);
	if (!entry)
		return NULL;
	return (VOID*)((UINT8*)module + *entry);
}

util::KLDR_DATA_TABLE_ENTRY* GetModuleFromList(LIST_ENTRY* head, const CHAR16* mod_name)
{
	for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink)
	{
		util::KLDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(it, util::KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (!u_wcsnicmp(entry->BaseDllName.Buffer, mod_name, entry->BaseDllName.Length))
		{
			return entry;
		}
	}
	return NULL;
}

 VOID* util::GetLoadedModuleBase(const unsigned short* mod_name)
{
	void* g_kernel_base = (void*)util::GetModuleBase(0);


	static LIST_ENTRY* PsLoadedModuleList;
	if (!PsLoadedModuleList)
		PsLoadedModuleList = (LIST_ENTRY*)FindExport(g_kernel_base, (const unsigned char*)"PsLoadedModuleList");

	KLDR_DATA_TABLE_ENTRY* module = GetModuleFromList(PsLoadedModuleList, mod_name);
	if (!module)
		return NULL;
	return module->DllBase;
}

void Set_Memory(VOID* Dest, unsigned __int64 Len, CHAR8 Val)
{
	for (int i = 0; i < Len; ++i)
	{
		((volatile UINT8*)Dest)[i] = Val;
	}
}

DWORD64 util::ResolveExport(PVOID imageBase, const char* functionName)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD64)imageBase + dosHeader->e_lfanew);

	DWORD exportBase = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportBaseSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!exportBase || !exportBaseSize)
		return 0;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)imageBase + exportBase);

	DWORD64 delta = (DWORD64)imageExportDirectory - exportBase;

	DWORD* nameTable = (DWORD*)(imageExportDirectory->AddressOfNames + delta);
	WORD* ordinalTable = (WORD*)(imageExportDirectory->AddressOfNameOrdinals + delta);
	DWORD* functionTable = (DWORD*)(imageExportDirectory->AddressOfFunctions + delta);

	for (DWORD i = 0u; i < imageExportDirectory->NumberOfNames; ++i)
	{
		const char* currentFunctionName = (const char*)(nameTable[i] + delta);

		if (CustomCompare(currentFunctionName, functionName) == 0)
		{
			WORD functionOrdinal = ordinalTable[i];
			if (functionTable[functionOrdinal] <= 0x1000)
				return 0;

			DWORD64 functionAddress = (DWORD64)imageBase + functionTable[functionOrdinal];

			if (functionAddress >= (DWORD64)imageBase + exportBase && functionAddress <= (DWORD64)imageBase + exportBase + exportBaseSize)
				return 0;

			return functionAddress;
		}
	}

	return 0;
}
