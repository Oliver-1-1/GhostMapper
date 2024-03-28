#pragma once
#include "utils.h"
#include "dumpDriver.h"

util::KLDR_DATA_TABLE_ENTRY* GetModuleFromList(LIST_ENTRY* head, const CHAR16* mod_name);
NTSTATUS Map(RTL_PROCESS_MODULE_INFORMATION* module);
NTSTATUS ApplyMap();

