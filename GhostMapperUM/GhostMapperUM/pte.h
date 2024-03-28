#pragma once
#include <Windows.h>
#include <Psapi.h>
#include "intel_driver.hpp"
#include "utils.hpp"

typedef unsigned __int64 QWORD;


typedef union _pte {
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


ppte GetPTEForVA(HANDLE IntelDriverHandle, uint64_t Address, uint64_t PteBaseAddress);
uint64_t FindMiGetPteSigAddress(uint64_t KernelBase);