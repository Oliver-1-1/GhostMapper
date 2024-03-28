#include <Windows.h>
#include <iostream>
#include "intel_driver.hpp"
#include <pte.h>
#include <vector>


bool RestoreOriginalDriver(HANDLE IntelDrvHandle ,uint64_t OriginalDriverBase, void* OriginalDriverMemory,uint64_t PatchSize, const std::vector<pte>& OriginalPtes ,uint64_t PteBaseAddress)
{
	if (!OriginalDriverBase || !OriginalDriverMemory)
		return false;

	// copy original driver image 
	if (!intel_driver::WriteMemory(IntelDrvHandle, OriginalDriverBase, OriginalDriverMemory, PatchSize))
	{
		Log(L"[*] failed to restore original driver image" << std::endl);
		return false;
	}

	// restore original ptes 
	uint64_t CurrentDriverAddress = OriginalDriverBase;

	for (pte OriginalPte : OriginalPtes)
	{
		uint64_t PteAddress = (uint64_t)GetPTEForVA(IntelDrvHandle, CurrentDriverAddress, PteBaseAddress);
		if (!intel_driver::WriteMemory(IntelDrvHandle, PteAddress, &OriginalPte, sizeof(pte)))
		{
			Log(L"[-] failed to restore original driver pte" << std::endl);
			return false;
		}
		CurrentDriverAddress += USN_PAGE_SIZE;
	}

	Log(L"[*] restored original driver in memory" << std::endl);

}