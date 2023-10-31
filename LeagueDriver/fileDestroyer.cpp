#include "fileDestroyer.h"

BOOLEAN DestroyDriverFile(CONST PCWSTR path) {
	UNICODE_STRING uniPath;
	IO_STATUS_BLOCK ioStatusBlock = { 0 }; // Needs memset
	HANDLE fileHandle = nullptr;
	NTSTATUS status = 0;

	RtlInitUnicodeString(&uniPath, path);
	OBJECT_ATTRIBUTES objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

	//if(WINVER_7 || WINVER_8.1 || !fileActive(path))
		//ZwDeleteFile(&objectAttributes)

	//credits to Fisher prince // null post on UC
	status = IoCreateFileEx(&fileHandle,
		SYNCHRONIZE | DELETE,
		&objectAttributes,
		&ioStatusBlock,
		nullptr,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
		nullptr,
		0,
		CreateFileTypeNone,
		nullptr,
		IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK,
		nullptr); // We could pass something here for unwanted minifilter drivers in the stack when accessing sensitive files


	if (status != STATUS_SUCCESS) return FALSE;

	PFILE_OBJECT fileObject;
	status = ObReferenceObjectByHandleWithTag(fileHandle, SYNCHRONIZE | DELETE, *IoFileObjectType, 0, 'eded', reinterpret_cast<PVOID*>(&fileObject), nullptr);
	if (status != STATUS_SUCCESS) {
		ObCloseHandle(fileHandle, 0);
		return FALSE;
	}

	const PSECTION_OBJECT_POINTERS sectionObjectPointer = fileObject->SectionObjectPointer;
	sectionObjectPointer->ImageSectionObject = nullptr;

	const BOOLEAN imageSectionFlushed = MmFlushImageSection(sectionObjectPointer, MmFlushForDelete);

	ObfDereferenceObject(fileObject);
	ObCloseHandle(fileHandle, 0);

	if (imageSectionFlushed) {
		status = ZwDeleteFile(&objectAttributes);
		return status ? FALSE : TRUE;
	}

	return FALSE;
}

BOOLEAN AddFile(CONST PCWSTR path, CONST PUCHAR file) {
	NTSTATUS status = 0;
	UNICODE_STRING uniPath;
	HANDLE handle;
	IO_STATUS_BLOCK ioStatusBlock;

	RtlInitUnicodeString(&uniPath, path);

	OBJECT_ATTRIBUTES objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

	status = ZwCreateFile(&handle, GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (status != STATUS_SUCCESS) {

		return FALSE;
	}

	status = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, (PVOID)file, sizeof(file), NULL, NULL);
	ZwClose(handle);

	return status ? FALSE : TRUE;
}

BOOLEAN AddDriverFile(CONST PCWSTR path, CONST PUCHAR file) {
	return AddFile(path, file);
}