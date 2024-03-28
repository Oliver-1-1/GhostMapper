#include <ntddk.h>

#define RESTORE true
#define RESTORE_EVENT L"\\BaseNamedObjects\\RestoreDrv"


NTSTATUS CustomDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrint("[*] mapped driver has been successfully loaded!!!\n");

	/*
	// signal restore event immidiately since we are doing nothing in this PoC driver...
	UNICODE_STRING RestoreEventName = RTL_CONSTANT_STRING(RESTORE_EVENT);
	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, &RestoreEventName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hEvent;
	NTSTATUS status = ZwOpenEvent(&hEvent, EVENT_ALL_ACCESS, &objattr);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[*] failed to open event 0x%x\n",status);
		return status;
	}

	 KeSetEvent(hEvent, 0, FALSE);
	 */
	// ZwClose(hEvent);
	

	return STATUS_SUCCESS;
}