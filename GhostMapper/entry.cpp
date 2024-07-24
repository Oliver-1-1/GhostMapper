#include <ntifs.h>
#include "mapper.hpp"

VOID DriverUnload(PDRIVER_OBJECT obj)
{
	UNREFERENCED_PARAMETER(obj);
	DbgPrintEx(0, 0, "Unload\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT obj, PUNICODE_STRING str)
{
	UNREFERENCED_PARAMETER(str);
	DbgPrintEx(0, 0, "Entry\n");
	
	obj->DriverUnload = DriverUnload;

	NTSTATUS status = MapGhostDriver("dump_dumpfve.sys");
	
	if (status == STATUS_SUCCESS)
	{
		DbgPrintEx(0, 0, "Driver was successfully mapped!\n");
	}
	else
	{
		DbgPrintEx(0, 0, "Driver could not be mapped! Status code: %x\n", status);
	}

	return STATUS_SUCCESS;
}