#include <Windows.h>
#include <Psapi.h>
#include "intel_driver.hpp"
#include "utils.hpp"
#include "pte.h"

uint64_t FindMiGetPteSigAddress(uint64_t KernelBase)
{
	int Matches = 0;

	unsigned char MiGetPteAddressSig[] =
	{
		0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x48, 0x23, 0xC8, 0x48, 0xB8
	};

	// map ntos to usermode 
	HMODULE uNt = LoadLibraryEx(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	DWORD64 uNtAddr = (DWORD64)uNt;
	void* ntoskrnl_ptr = (void*)uNt;

	bool Found = false;

	MODULEINFO modinfo;
	GetModuleInformation(GetCurrentProcess(), uNt, &modinfo, sizeof(modinfo));


	// scan for signature  
	DWORD64 MiGetPteAddressSigAddressUM = 0x0;
	for (unsigned int i = 0; i < modinfo.SizeOfImage; i++)
	{
		if (Found)
			break;
		for (int j = 0; j < sizeof(MiGetPteAddressSig); j++)
		{
			unsigned char chr = *(char*)(uNtAddr + i + j);
			if (MiGetPteAddressSig[j] != chr)
			{

				break;
			}
			if (j + 1 == sizeof(MiGetPteAddressSig))
			{
				// we want the second match 
				Matches++;
				if (Matches > 1)
				{
					Found = true;
					MiGetPteAddressSigAddressUM = uNtAddr + i + sizeof(MiGetPteAddressSig);
				}
			}
		}
	}

	if (!Found)
		return NULL;

	uint64_t MiGetPteSigAddressKM = MiGetPteAddressSigAddressUM - uNtAddr + KernelBase;


	return MiGetPteSigAddressKM;
}

ULONG_PTR GetPTE(ULONG_PTR pteBase, ULONG_PTR address) {
	ULONG_PTR PTEBase = pteBase;
	address = address >> 9;
	address &= 0x7FFFFFFFF8;
	address += (ULONG_PTR)PTEBase;

	return address;
}

ppte GetPTEForVA(HANDLE IntelDriverHandle,uint64_t Address, uint64_t PteBaseAddress)
{


	void* PteBase = nullptr;
	if (!intel_driver::ReadMemory(IntelDriverHandle, PteBaseAddress, &PteBase, sizeof(void*)))
		return nullptr;

	ppte pte = (ppte)GetPTE((ULONG_PTR)PteBase, (ULONG_PTR)Address);

	Log(L"[*] pte: 0x" << std::hex << pte << std::endl);
	
	return pte;

}