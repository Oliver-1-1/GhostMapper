#include <intrin.h>
#include "mapper.h"
EXTERN_C int _fltused = 0;

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT obj, PUNICODE_STRING str) {
	UNREFERENCED_PARAMETER(obj);
	UNREFERENCED_PARAMETER(str);

	ApplyMap();

	return STATUS_SUCCESS;
}