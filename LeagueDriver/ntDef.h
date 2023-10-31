#pragma once
#include <ntifs.h>
//#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#pragma warning (disable: 4214) // nonstandard extension used : bit field types other than int
#pragma warning (disable: 4201) // nonstandard extension used : nameless struct / union
typedef unsigned __int8  BYTE;
typedef unsigned __int16 WORD;
typedef unsigned __int64 QWORD;
#define NUMBER_HASH_BUCKETS 37
#define ERROR -1

//#define DEBUG_USER
#ifdef DEBUG_USER
#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...)
#define DEBUG_ERROR(fmt, ...)
#endif

typedef ULONG KEPROCESSORINDEX; /**< Bitmap indexes != process numbers, apparently. */
typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONGLONG Bitmap[20];

} KAFFINITY_EX, * PKAFFINITY_EX;

EXTERN_C NTSYSAPI BOOLEAN  NTAPI KeInterlockedSetProcessorAffinityEx(PKAFFINITY_EX pAffinity, KEPROCESSORINDEX idxProcessor);
EXTERN_C NTSYSAPI __int64  NTAPI KeAndGroupAffinityEx(unsigned __int32* a1, __int64 a2, char* a3);
EXTERN_C NTKERNELAPI UCHAR* NTAPI 	PsGetProcessImageFileName(_In_ PEPROCESS process);


/* invalid drivers linked list items */

typedef struct _INVALID_DRIVER
{
	struct _INVALID_DRIVER* next;
	PDRIVER_OBJECT driver;

}INVALID_DRIVER, * PINVALID_DRIVER;

typedef struct _INVALID_DRIVERS_HEAD
{
	PINVALID_DRIVER first_entry;
	INT count;		//keeps track of the number of drivers in the list

}INVALID_DRIVERS_HEAD, * PINVALID_DRIVERS_HEAD;

/* system modules information */

typedef struct _SYSTEM_MODULES
{
	PVOID address;
	INT module_count;

}SYSTEM_MODULES, * PSYSTEM_MODULES;


typedef struct _DRIVER_OBJECTS
{
	PVOID address;
	INT module_count;

}DRIVER_OBJECTS, * PDRIVER_OBJECTS;



typedef struct _OBJECT_DIRECTORY_ENTRY
{
	struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;

} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
	EX_PUSH_LOCK Lock;
	struct _DEVICE_MAP* DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;

} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _DEVICE_MAP
{
	struct _OBJECT_DIRECTORY* DosDevicesDirectory;
	struct _OBJECT_DIRECTORY* GlobalDosDevicesDirectory;
	ULONG ReferenceCount;
	ULONG DriveMap;
	UCHAR DriveType[32];

} DEVICE_MAP, * PDEVICE_MAP;

typedef struct _RTL_MODULE_EXTENDED_INFO
{
	PVOID ImageBase;
	ULONG ImageSize;
	USHORT FileNameOffset;
	CHAR FullPathName[0x100];

} RTL_MODULE_EXTENDED_INFO, * PRTL_MODULE_EXTENDED_INFO;


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemInformationClassMin = 0,
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemNotImplemented1 = 4,
	SystemProcessInformation = 5,
	SystemProcessesAndThreadsInformation = 5,
	SystemCallCountInfoInformation = 6,
	SystemCallCounts = 6,
	SystemDeviceInformation = 7,
	SystemConfigurationInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemProcessorTimes = 8,
	SystemFlagsInformation = 9,
	SystemGlobalFlag = 9,
	SystemCallTimeInformation = 10,
	SystemNotImplemented2 = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemLockInformation = 12,
	SystemStackTraceInformation = 13,
	SystemNotImplemented3 = 13,
	SystemPagedPoolInformation = 14,
	SystemNotImplemented4 = 14,
	SystemNonPagedPoolInformation = 15,
	SystemNotImplemented5 = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemPagefileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemInstructionEmulationCounts = 19,
	SystemVdmBopInformation = 20,
	SystemInvalidInfoClass1 = 20,
	SystemFileCacheInformation = 21,
	SystemCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemProcessorStatistics = 23,
	SystemDpcBehaviourInformation = 24,
	SystemDpcInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemNotImplemented6 = 25,
	SystemLoadImage = 26,
	SystemUnloadImage = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemTimeAdjustment = 28,
	SystemSummaryMemoryInformation = 29,
	SystemNotImplemented7 = 29,
	SystemNextEventIdInformation = 30,
	SystemNotImplemented8 = 30,
	SystemEventIdsInformation = 31,
	SystemNotImplemented9 = 31,
	SystemCrashDumpInformation = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLoadAndCallImage = 38,
	SystemPrioritySeparation = 39,
	SystemPlugPlayBusInformation = 40,
	SystemNotImplemented10 = 40,
	SystemDockInformation = 41,
	SystemNotImplemented11 = 41,
	SystemInvalidInfoClass2 = 42,
	SystemProcessorSpeedInformation = 43,
	SystemInvalidInfoClass3 = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemSetTimeSlipEvent = 46,
	SystemCreateSession = 47,
	SystemDeleteSession = 48,
	SystemInvalidInfoClass4 = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemAddVerifier = 52,
	SystemSessionProcessesInformation = 53,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;



typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];

} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


extern "C" NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

//This will trigger patch-guard D:


typedef struct _LDR_DATA_TABLE_ENTRY
{
	/* 0x0000 */ struct _LIST_ENTRY InLoadOrderLinks;
	/* 0x0010 */ struct _LIST_ENTRY InMemoryOrderLinks;
	/* 0x0020 */ struct _LIST_ENTRY InInitializationOrderLinks;
	/* 0x0030 */ void* DllBase;
	/* 0x0038 */ void* EntryPoint;
	/* 0x0040 */ unsigned long SizeOfImage;
	/* 0x0044 */ long Padding_1;
	/* 0x0048 */ struct _UNICODE_STRING FullDllName;
	/* 0x0058 */ struct _UNICODE_STRING BaseDllName;
	union
	{
		/* 0x0068 */ unsigned char FlagGroup[4];
		/* 0x0068 */ unsigned long Flags;
		struct /* bitfield */
		{
			/* 0x0068 */ unsigned long PackagedBinary : 1; /* bit position: 0 */
			/* 0x0068 */ unsigned long MarkedForRemoval : 1; /* bit position: 1 */
			/* 0x0068 */ unsigned long ImageDll : 1; /* bit position: 2 */
			/* 0x0068 */ unsigned long LoadNotificationsSent : 1; /* bit position: 3 */
			/* 0x0068 */ unsigned long TelemetryEntryProcessed : 1; /* bit position: 4 */
			/* 0x0068 */ unsigned long ProcessStaticImport : 1; /* bit position: 5 */
			/* 0x0068 */ unsigned long InLegacyLists : 1; /* bit position: 6 */
			/* 0x0068 */ unsigned long InIndexes : 1; /* bit position: 7 */
			/* 0x0068 */ unsigned long ShimDll : 1; /* bit position: 8 */
			/* 0x0068 */ unsigned long InExceptionTable : 1; /* bit position: 9 */
			/* 0x0068 */ unsigned long ReservedFlags1 : 2; /* bit position: 10 */
			/* 0x0068 */ unsigned long LoadInProgress : 1; /* bit position: 12 */
			/* 0x0068 */ unsigned long LoadConfigProcessed : 1; /* bit position: 13 */
			/* 0x0068 */ unsigned long EntryProcessed : 1; /* bit position: 14 */
			/* 0x0068 */ unsigned long ProtectDelayLoad : 1; /* bit position: 15 */
			/* 0x0068 */ unsigned long ReservedFlags3 : 2; /* bit position: 16 */
			/* 0x0068 */ unsigned long DontCallForThreads : 1; /* bit position: 18 */
			/* 0x0068 */ unsigned long ProcessAttachCalled : 1; /* bit position: 19 */
			/* 0x0068 */ unsigned long ProcessAttachFailed : 1; /* bit position: 20 */
			/* 0x0068 */ unsigned long CorDeferredValidate : 1; /* bit position: 21 */
			/* 0x0068 */ unsigned long CorImage : 1; /* bit position: 22 */
			/* 0x0068 */ unsigned long DontRelocate : 1; /* bit position: 23 */
			/* 0x0068 */ unsigned long CorILOnly : 1; /* bit position: 24 */
			/* 0x0068 */ unsigned long ChpeImage : 1; /* bit position: 25 */
			/* 0x0068 */ unsigned long ReservedFlags5 : 2; /* bit position: 26 */
			/* 0x0068 */ unsigned long Redirected : 1; /* bit position: 28 */
			/* 0x0068 */ unsigned long ReservedFlags6 : 2; /* bit position: 29 */
			/* 0x0068 */ unsigned long CompatDatabaseProcessed : 1; /* bit position: 31 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x006c */ unsigned short ObsoleteLoadCount;
	/* 0x006e */ unsigned short TlsIndex;
	/* 0x0070 */ struct _LIST_ENTRY HashLinks;
	/* 0x0080 */ unsigned long TimeDateStamp;
	/* 0x0084 */ long Padding_2;
	/* 0x0088 */ struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	/* 0x0090 */ void* Lock;
	/* 0x0098 */ struct _LDR_DDAG_NODE* DdagNode;
	/* 0x00a0 */ struct _LIST_ENTRY NodeModuleLink;
	/* 0x00b0 */ struct _LDRP_LOAD_CONTEXT* LoadContext;
	/* 0x00b8 */ void* ParentDllBase;
	/* 0x00c0 */ void* SwitchBackContext;
	/* 0x00c8 */ struct _RTL_BALANCED_NODE BaseAddressIndexNode;
	/* 0x00e0 */ struct _RTL_BALANCED_NODE MappingInfoIndexNode;
	/* 0x00f8 */ unsigned __int64 OriginalBase;
	/* 0x0100 */ union _LARGE_INTEGER LoadTime;
	/* 0x0108 */ unsigned long BaseNameHashValue;
	/* 0x010c */ enum _LDR_DLL_LOAD_REASON LoadReason;
	/* 0x0110 */ unsigned long ImplicitPathOptions;
	/* 0x0114 */ unsigned long ReferenceCount;
	/* 0x0118 */ unsigned long DependentLoadFlags;
	/* 0x011c */ unsigned char SigningLevel;
	/* 0x011d */ char __PADDING__[3];
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY; /* size: 0x0120 */

typedef union _KEXECUTE_OPTIONS
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned char ExecuteDisable : 1; /* bit position: 0 */
			/* 0x0000 */ unsigned char ExecuteEnable : 1; /* bit position: 1 */
			/* 0x0000 */ unsigned char DisableThunkEmulation : 1; /* bit position: 2 */
			/* 0x0000 */ unsigned char Permanent : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned char ExecuteDispatchEnable : 1; /* bit position: 4 */
			/* 0x0000 */ unsigned char ImageDispatchEnable : 1; /* bit position: 5 */
			/* 0x0000 */ unsigned char DisableExceptionChainValidation : 1; /* bit position: 6 */
			/* 0x0000 */ unsigned char Spare : 1; /* bit position: 7 */
		}; /* bitfield */
		/* 0x0000 */ volatile unsigned char ExecuteOptions;
		/* 0x0000 */ unsigned char ExecuteOptionsNV;
	}; /* size: 0x0001 */
} KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS; /* size: 0x0001 */
typedef union _KSTACK_COUNT
{
	union
	{
		/* 0x0000 */ long Value;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned long State : 3; /* bit position: 0 */
			/* 0x0000 */ unsigned long StackCount : 29; /* bit position: 3 */
		}; /* bitfield */
	}; /* size: 0x0004 */
} KSTACK_COUNT, * PKSTACK_COUNT; /* size: 0x0004 */

typedef struct _KPROCESS
{
	/* 0x0000 */ struct _DISPATCHER_HEADER Header;
	/* 0x0018 */ struct _LIST_ENTRY ProfileListHead;
	/* 0x0028 */ unsigned __int64 DirectoryTableBase;
	/* 0x0030 */ struct _LIST_ENTRY ThreadListHead;
	/* 0x0040 */ unsigned long ProcessLock;
	/* 0x0044 */ unsigned long ProcessTimerDelay;
	/* 0x0048 */ unsigned __int64 DeepFreezeStartTime;
	/* 0x0050 */ struct _KAFFINITY_EX Affinity;
	/* 0x00f8 */ unsigned __int64 AffinityPadding[12];
	/* 0x0158 */ struct _LIST_ENTRY ReadyListHead;
	/* 0x0168 */ struct _SINGLE_LIST_ENTRY SwapListEntry;
	/* 0x0170 */ volatile struct _KAFFINITY_EX ActiveProcessors;
	/* 0x0218 */ unsigned __int64 ActiveProcessorsPadding[12];
	union
	{
		struct /* bitfield */
		{
			/* 0x0278 */ unsigned long AutoAlignment : 1; /* bit position: 0 */
			/* 0x0278 */ unsigned long DisableBoost : 1; /* bit position: 1 */
			/* 0x0278 */ unsigned long DisableQuantum : 1; /* bit position: 2 */
			/* 0x0278 */ unsigned long DeepFreeze : 1; /* bit position: 3 */
			/* 0x0278 */ unsigned long TimerVirtualization : 1; /* bit position: 4 */
			/* 0x0278 */ unsigned long CheckStackExtents : 1; /* bit position: 5 */
			/* 0x0278 */ unsigned long CacheIsolationEnabled : 1; /* bit position: 6 */
			/* 0x0278 */ unsigned long PpmPolicy : 3; /* bit position: 7 */
			/* 0x0278 */ unsigned long VaSpaceDeleted : 1; /* bit position: 10 */
			/* 0x0278 */ unsigned long ReservedFlags : 21; /* bit position: 11 */
		}; /* bitfield */
		/* 0x0278 */ volatile long ProcessFlags;
	}; /* size: 0x0004 */
	/* 0x027c */ unsigned long ActiveGroupsMask;
	/* 0x0280 */ char BasePriority;
	/* 0x0281 */ char QuantumReset;
	/* 0x0282 */ char Visited;
	/* 0x0283 */ union _KEXECUTE_OPTIONS Flags;
	/* 0x0284 */ unsigned short ThreadSeed[20];
	/* 0x02ac */ unsigned short ThreadSeedPadding[12];
	/* 0x02c4 */ unsigned short IdealProcessor[20];
	/* 0x02ec */ unsigned short IdealProcessorPadding[12];
	/* 0x0304 */ unsigned short IdealNode[20];
	/* 0x032c */ unsigned short IdealNodePadding[12];
	/* 0x0344 */ unsigned short IdealGlobalNode;
	/* 0x0346 */ unsigned short Spare1;
	/* 0x0348 */ volatile union _KSTACK_COUNT StackCount;
	/* 0x034c */ long Padding_0;
	/* 0x0350 */ struct _LIST_ENTRY ProcessListEntry;
	/* 0x0360 */ unsigned __int64 CycleTime;
	/* 0x0368 */ unsigned __int64 ContextSwitches;
	/* 0x0370 */ struct _KSCHEDULING_GROUP* SchedulingGroup;
	/* 0x0378 */ unsigned long FreezeCount;
	/* 0x037c */ unsigned long KernelTime;
	/* 0x0380 */ unsigned long UserTime;
	/* 0x0384 */ unsigned long ReadyTime;
	/* 0x0388 */ unsigned __int64 UserDirectoryTableBase;
	/* 0x0390 */ unsigned char AddressPolicy;
	/* 0x0391 */ unsigned char Spare2[71];
	/* 0x03d8 */ void* InstrumentationCallback;
	union
	{
		union
		{
			/* 0x03e0 */ unsigned __int64 SecureHandle;
			struct
			{
				struct /* bitfield */
				{
					/* 0x03e0 */ unsigned __int64 SecureProcess : 1; /* bit position: 0 */
					/* 0x03e0 */ unsigned __int64 Unused : 1; /* bit position: 1 */
				}; /* bitfield */
			} /* size: 0x0008 */ Flags;
		}; /* size: 0x0008 */
	} /* size: 0x0008 */ SecureState;
	/* 0x03e8 */ unsigned __int64 KernelWaitTime;
	/* 0x03f0 */ unsigned __int64 UserWaitTime;
	/* 0x03f8 */ unsigned __int64 EndPadding[8];
} KPROCESS, * PKPROCESS; /* size: 0x0438 */

