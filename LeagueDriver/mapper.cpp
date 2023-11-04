#include "mapper.h"


static VOID to_lower(CHAR* in, CHAR* out){
	INT i = -1;
	while (in[++i] != '\x00') out[i] = (CHAR)tolower(in[i]);
}

NTSTATUS ApplyMap() {

	while (1) {

		VOID* module_list = util::GetModuleList();
		if (!module_list) continue;
		
		RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;

		for (ULONG i = 1; i < modules->NumberOfModules; ++i) {
			RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[i];
			CHAR driver_name[0x0100] = { 0 };
			to_lower((CHAR*)module->FullPathName, driver_name);

			if (!strstr(driver_name, "dumpfve.sys")) {
				continue;
			}

			Map(module);

			ExFreePool(module_list);
			return 0;
		}
		ExFreePool(module_list);
		util::Sleep(10);

	}

	return 0;
}

extern "C" {
	__int64(__fastcall* MiGetPteAddress)(unsigned __int64 a1);
	NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineNam);
}


typedef union _pte{
	QWORD value;
	struct
	{
		QWORD present : 1;
		QWORD rw : 1;
		QWORD user_supervisor : 1;
		QWORD page_write_through : 1;
		QWORD page_cache : 1;
		QWORD accessed : 1;
		QWORD dirty : 1;
		QWORD access_type : 1;
		QWORD global : 1;
		QWORD ignore_2 : 3;
		QWORD pfn : 36;
		QWORD reserved : 4;
		QWORD ignore_3 : 7;
		QWORD pk : 4;
		QWORD nx : 1;
	};
} pte, * ppte;


ppte GetPte(ULONGLONG addr) {
	if (MmGetPhysicalAddress((PVOID)(addr)).QuadPart == 0) {
		return 0;
	}

	if (!MmIsAddressValid((PVOID)(addr))) {
		return 0;
	}

	ppte pte = (ppte)MiGetPteAddress(addr);
	if (!pte || !pte->present) {
		return 0;
	}

	return pte;
}

NTSTATUS Map(RTL_PROCESS_MODULE_INFORMATION* module) {
	PVOID base = module->ImageBase;
	ULONG size = module->ImageSize;

	PVOID ntoskrnl = util::GetModuleBase(0);

	QWORD MmUnlockPreChargedPagedPoolAddress = (QWORD)RtlFindExportedRoutineByName(ntoskrnl, "MmUnlockPreChargedPagedPool");
	if (!MmUnlockPreChargedPagedPoolAddress) return STATUS_UNSUCCESSFUL;
	*(QWORD*)&MiGetPteAddress = (QWORD)(*(int*)(MmUnlockPreChargedPagedPoolAddress + 8) + MmUnlockPreChargedPagedPoolAddress + 12);

	//Get the right pe header information. and validate signatures
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)RuntimeDriver;
	if (dos->e_magic != 'ZM') return STATUS_UNSUCCESSFUL;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(RuntimeDriver + dos->e_lfanew);
	if (nt->Signature != (UINT32)'EP') return STATUS_UNSUCCESSFUL;

	//Allocate memory for our local driver to be prepared.
	PMDL mdl = MmAllocatePagesForMdl({ 0 }, { ~0ul }, { 0 }, nt->OptionalHeader.SizeOfImage);
	BYTE* allocation = (BYTE*)MmMapLockedPages(mdl, KernelMode);

	memcpy(allocation, RuntimeDriver, nt->FileHeader.SizeOfOptionalHeader);


	ppte pte = GetPte((ULONGLONG)base);
	if (!pte) return STATUS_UNSUCCESSFUL;
	pte->nx = true;
	pte->rw = true;

	// Copy sections one at a time
	PIMAGE_SECTION_HEADER sec_hdr = (PIMAGE_SECTION_HEADER)((BYTE*)(&nt->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec_hdr++) {
		memcpy(allocation + sec_hdr->VirtualAddress, RuntimeDriver + sec_hdr->PointerToRawData, sec_hdr->SizeOfRawData);

		ppte pte = GetPte((ULONGLONG)base + sec_hdr->VirtualAddress);
		if (!pte) return STATUS_UNSUCCESSFUL;

		//Sections could be larger than 0x1000 bytes, u will have to size of section/0x1000. to get all pages and change protection so.
		if (!strcmp((const char*)sec_hdr->Name, ".text")) {
			//for(int i = 0; i < sec_hdr->SizeOfRawData / 0x1000; i++){ and do this for all pages.
				//pte = GetPte((ULONGLONG)base + sec_hdr->VirtualAddress + 0x1000*i);
				//pte->nx = false;
				//pte->rw = false;
			//}
			pte->nx = false;
			pte->rw = false;
		}
		else if (!strcmp((const char*)sec_hdr->Name, ".data")) {
			
			pte->nx = true;
			pte->rw = true;
		}
		else {
			pte->nx = false;
			pte->rw = false;
		}

	}

	//CODE FROM XIGMAPPER
	// Imports
	PIMAGE_DATA_DIRECTORY import_dir = &nt->OptionalHeader.DataDirectory[1];
	for (PIMAGE_IMPORT_DESCRIPTOR2 desc = (PIMAGE_IMPORT_DESCRIPTOR2)(allocation + import_dir->VirtualAddress); desc->LookupTableRVA; ++desc)
	{
		// Get unicode name from ascii name
		CHAR16 buffer[260];
		CHAR8* mod_name = (CHAR8*)(allocation + desc->Name);
		for (int i = 0; i < 259 && mod_name[i]; ++i)
			buffer[i] = (CHAR16)mod_name[i], buffer[i + 1] = L'\0';
		PVOID module_base = util::GetLoadedModuleBase(buffer);
		for (UINT64* lookup_entry = (UINT64*)(allocation + desc->LookupTableRVA), *iat_entry = (UINT64*)(allocation + desc->ImportAddressTable); *lookup_entry; ++lookup_entry, ++iat_entry)
		{
			if (*lookup_entry & (1ull << 63))
				*(PVOID*)iat_entry = util::FindExportByOrdinal(module_base, *lookup_entry & 0xFFFF);
			else
				*(PVOID*)iat_entry = util::FindExport(module_base, ((RELOC_NAME_TABLE_ENTRY*)(allocation + (*lookup_entry & 0x7FFFFFFF)))->Name);
		}
	}

	// Relocations
	INT64 load_delta = (INT64)(allocation - nt->OptionalHeader.ImageBase);
	PIMAGE_DATA_DIRECTORY reloc = &nt->OptionalHeader.DataDirectory[5];
	for (PRELOC_BLOCK_HDR i = (PRELOC_BLOCK_HDR)(allocation + reloc->VirtualAddress); i < (PRELOC_BLOCK_HDR)(allocation + reloc->VirtualAddress + reloc->Size); *(BYTE**)&i += i->BlockSize)
		for (PRELOC_ENTRY entry = (PRELOC_ENTRY)i + 4; (BYTE*)entry < (BYTE*)i + i->BlockSize; ++entry)
			if (entry->Type == 0xA)
				*(UINT64*)(allocation + i->PageRVA + entry->Offset) += load_delta;

	// Unload discardable sections
	sec_hdr = (PIMAGE_SECTION_HEADER)((BYTE*)(&nt->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec_hdr++)
		if (sec_hdr->Characteristics & 0x02000000)
			memset(allocation + sec_hdr->VirtualAddress, 0x00, sec_hdr->SizeOfRawData);

	if (!nt->OptionalHeader.AddressOfEntryPoint)
		return STATUS_UNSUCCESSFUL;

	//END CODE FROM XIGMAPPER


	//Zero the memory in the driver so we dont have any information left in it.
	util::ZeroMemory(base, size);


	//Patch in our driver :D
	util::WriteToProtectedMem((void*)(QWORD)base, (BYTE*)allocation, nt->OptionalHeader.SizeOfImage);


	//Now we can free the pool since we have already patch in the driver. Also zero it out so it can be traced.
	RtlZeroMemory(allocation, nt->OptionalHeader.SizeOfImage); // First zero it out so it cant be found :D
	MmUnmapLockedPages(allocation, mdl);
	MmFreePagesFromMdl(mdl);
	ExFreePool(mdl);

	////Call our main point from target driver base + offset to DriverEntry
	unsigned long long(*DriverEntry)(PDRIVER_OBJECT obj, PUNICODE_STRING str) =
		(unsigned long long(*)(PDRIVER_OBJECT, PUNICODE_STRING))(((BYTE*)base + nt->OptionalHeader.AddressOfEntryPoint));


	DriverEntry((PDRIVER_OBJECT)0, (PUNICODE_STRING)0);

	return STATUS_SUCCESS;


}
