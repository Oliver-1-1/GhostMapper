#include "mapper.hpp"
EXTERN_C __int64(__fastcall* MiGetPteAddress)(unsigned __int64 a1) = 0;

VOID ToLower(CHAR* in) 
{
	int i = -1;
	while (in[++i] != '\x00') in[i] = (CHAR)tolower(in[i]);
}

NTSTATUS GetSystemModuleInformation(LPCSTR name, PRTL_PROCESS_MODULE_INFORMATION module)
{
	BOOL found = FALSE;
	ULONG length = 0;

	if (module == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	//This should fail because of the buffer being 0 so we can retrive the size
	ZwQuerySystemInformation(SystemModuleInformation, 0, length, &length);

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, length, 'ZPTA');

	if (modules == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, modules, length, &length);

	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	PRTL_PROCESS_MODULE_INFORMATION imodule = modules->Modules;
	if (modules->NumberOfModules > 0) 
	{
		if (!name) 
		{
			*module = modules->Modules[0]; //ntos
			found = TRUE;
		}
		else 
		{
			for (int i = 0; i < modules->NumberOfModules; i++) 
			{
				ToLower((CHAR*)imodule[i].FullPathName);
				//This is a little hack
				if (strstr((CHAR*)imodule[i].FullPathName, name)) 
				{
					*module = imodule[i];
					found = TRUE;
				}
			}
		}
	}

	if (modules) 
	{
		ExFreePoolWithTag(modules, 'ZPTA');
	}

	return found ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS MapGhostDriver(LPCSTR name)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (name == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RTL_PROCESS_MODULE_INFORMATION module;
	status = GetSystemModuleInformation(name, &module);

	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	status = PatchMemory(module);

	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	return STATUS_SUCCESS;
}

UINT64 ZGetProcAddress(UINT64 base, PCSTR export_name) 
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((UINT64)base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

	IMAGE_DATA_DIRECTORY exp = nt->OptionalHeader.DataDirectory[0];
	IMAGE_EXPORT_DIRECTORY* dir = (IMAGE_EXPORT_DIRECTORY*)(base + exp.VirtualAddress);

	PDWORD addresses = (PDWORD)(base + dir->AddressOfFunctions);
	PDWORD names = (PDWORD)(base + dir->AddressOfNames);
	UINT16* ordinals = (UINT16*)(base + dir->AddressOfNameOrdinals);

	for (int i = 0; i < dir->NumberOfNames; i++) 
	{
		PCSTR name = (PCSTR)(base + names[i]);
		if (!_stricmp(name, export_name)) 
		{
			return base + addresses[ordinals[i]];
		}
	}

	return 0;
}

NTSTATUS PatchMemory(RTL_PROCESS_MODULE_INFORMATION module)
{

	//Get the right pe header information. and validate signatures
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)DumpDriver;

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return STATUS_UNSUCCESSFUL;
	}

	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(DumpDriver + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//Allocate a buffer to prepare the driver to be patched in.
	PMDL mdl = MmAllocatePagesForMdl({ 0 }, { ~0ul }, { 0 }, nt->OptionalHeader.SizeOfImage);
	BYTE* allocation = (BYTE*)MmMapLockedPages(mdl, KernelMode);

	RtlCopyMemory(allocation, DumpDriver, nt->FileHeader.SizeOfOptionalHeader);

	// Copy sections one at a time
	PIMAGE_SECTION_HEADER sec_hdr = (PIMAGE_SECTION_HEADER)((BYTE*)(&nt->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec_hdr++)
	{
		RtlCopyMemory(allocation + sec_hdr->VirtualAddress, DumpDriver + sec_hdr->PointerToRawData, sec_hdr->SizeOfRawData);
	}

	//Imports
	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(nt->OptionalHeader.DataDirectory[1].VirtualAddress + allocation);
	while (import->Name) 
	{
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(allocation + import->OriginalFirstThunk);
		PIMAGE_THUNK_DATA fthunk = (PIMAGE_THUNK_DATA)(allocation + import->FirstThunk);
		while (thunk->u1.AddressOfData) 
		{
			LPCSTR name = (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) ? (LPCSTR)(thunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)(allocation + thunk->u1.AddressOfData))->Name;
			RTL_PROCESS_MODULE_INFORMATION temp;
			NTSTATUS status = GetSystemModuleInformation(((LPCSTR)(allocation + import->Name)), &temp);
			if (status == STATUS_SUCCESS) 
			{
				*(PVOID*)fthunk = (PVOID)ZGetProcAddress((UINT64)temp.ImageBase, name);
			}
			thunk++, fthunk++;
		}
		import++;
	}

	// Relocations
	INT64 delta = (INT64)(allocation - nt->OptionalHeader.ImageBase);
	PIMAGE_DATA_DIRECTORY reloc = &nt->OptionalHeader.DataDirectory[5];
	for (PRELOC_BLOCK_HDR i = (PRELOC_BLOCK_HDR)(allocation + reloc->VirtualAddress); i < (PRELOC_BLOCK_HDR)(allocation + reloc->VirtualAddress + reloc->Size); *(BYTE**)&i += i->BlockSize)
		for (PRELOC_ENTRY entry = (PRELOC_ENTRY)i + 4; (BYTE*)entry < (BYTE*)i + i->BlockSize; ++entry)
			if (entry->Type == 10)
				*(UINT64*)(allocation + i->PageRVA + entry->Offset) += delta;

	// Discardable sections
	sec_hdr = (PIMAGE_SECTION_HEADER)((PUCHAR)(&nt->FileHeader) + nt->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec_hdr++)
		if (sec_hdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			memset(allocation + sec_hdr->VirtualAddress, 0x00, sec_hdr->SizeOfRawData);

	if (!nt->OptionalHeader.AddressOfEntryPoint)
		return STATUS_UNSUCCESSFUL;

	//Zero the memory in the driver so we dont have any information left in it.
	ZeroMemory(module.ImageBase, module.ImageSize);

	//Patch in our driver :D
	WriteToProtectedMemory((void*)module.ImageBase, (BYTE*)allocation, nt->OptionalHeader.SizeOfImage);

	//Now we can free the pool since we have already patch in the driver. Also zero it out so it can be traced.
	RtlZeroMemory(allocation, nt->OptionalHeader.SizeOfImage);
	MmUnmapLockedPages(allocation, mdl);
	MmFreePagesFromMdl(mdl);
	ExFreePool(mdl);

	//Make sure header pte matches
	for (int i = 0; i < SIZE_TO_PAGES(nt->FileHeader.SizeOfOptionalHeader); i++)
	{
		PPte pte = GetPte((UINT64)module.ImageBase + i * PAGE_SIZE);

		if (pte == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}

		pte->nx = true;
		pte->rw = false;
	}
	
	sec_hdr = (PIMAGE_SECTION_HEADER)((PUCHAR)(&nt->FileHeader) + nt->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec_hdr++)
	{
		for (int j = 0; j < SIZE_TO_PAGES(sec_hdr->Misc.VirtualSize); j++)
		{
			//Match the pte aswell
			PPte pte = GetPte((ULONGLONG)(UINT64)module.ImageBase + sec_hdr->VirtualAddress + PAGE_SIZE * j);
			if (pte == NULL)
			{
				continue;
			}

			pte->nx = true;
			pte->rw = false;
			if (sec_hdr->Characteristics & IMAGE_SCN_CNT_CODE || sec_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				pte->nx = false;
			}
			if (sec_hdr->Characteristics & IMAGE_SCN_MEM_WRITE)
			{
				pte->rw = true;
			}
			
		}
	}

	//Call our main point from target driver base + offset to DriverEntry
	UINT64(*DriverEntry)(PDRIVER_OBJECT obj, PUNICODE_STRING str) = (UINT64(*)(PDRIVER_OBJECT, PUNICODE_STRING))(((BYTE*)module.ImageBase + nt->OptionalHeader.AddressOfEntryPoint));

	DriverEntry((PDRIVER_OBJECT)NULL, (PUNICODE_STRING)NULL);

	return STATUS_SUCCESS;
}

PPte GetPte(UINT64 pa)
{
	if (MmGetPhysicalAddress((PVOID)(pa)).QuadPart == 0)
	{
		return NULL;
	}

	if (!MmIsAddressValid((PVOID)(pa)))
	{
		return NULL;
	}

	if (MiGetPteAddress == NULL)
	{
		UNICODE_STRING uni;
		RtlInitUnicodeString(&uni, L"MmUnlockPreChargedPagedPool");
		UINT64 routine = (UINT64)MmGetSystemRoutineAddress(&uni);
		*(UINT64*)&MiGetPteAddress = (UINT64)(*(int*)(routine + 8) + routine + 12);
	}

	PPte pte = (PPte)MiGetPteAddress(pa);
	if (!pte || !pte->present) 
	{
		return NULL;
	}

	return pte;
}

NTSTATUS WriteToProtectedMemory(PVOID address, PUCHAR source, ULONG length) 
{
	MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
	if (mdl == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	PVOID map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (map == NULL)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (status) 
	{
		MmUnmapLockedPages(map, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	RtlCopyMemory(map, source, length);
	MmUnmapLockedPages(map, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return STATUS_SUCCESS;
}

NTSTATUS ZeroMemory(PVOID address, ULONG length)
{
	MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
	if (mdl == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	PVOID map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (map == NULL)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (status)
	{
		MmUnmapLockedPages(map, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(map, length);

	MmUnmapLockedPages(map, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return STATUS_SUCCESS;
}
