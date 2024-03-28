#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>

bool RestoreOriginalDriver(HANDLE IntelDrvHandle, uint64_t OriginalDriverBase, void* OriginalDriverMemory, uint64_t PatchSize, const std::vector<pte>& OriginalPtes, uint64_t PteBaseAddress);
