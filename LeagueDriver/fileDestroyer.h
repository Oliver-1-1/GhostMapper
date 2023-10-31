#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>


BOOLEAN DestroyDriverFile(CONST PCWSTR path);
BOOLEAN AddFile(CONST PCWSTR path, CONST PUCHAR file);
BOOLEAN AddDriverFile(CONST PCWSTR path, CONST PUCHAR file); // Just a wrapper around AddFile