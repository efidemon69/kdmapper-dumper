#pragma once
#include <ntifs.h>
#include <intrin.h>

#if true
#define DBG_PRINT(...) DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[kdstinker]" __VA_ARGS__);
#else
#define DBG_PRINT(...)
#endif

#ifndef DWORD
#define DWORD unsigned
#endif

#ifndef WORD
#define WORD unsigned short
#endif

#ifndef uint64_t
#define uint64_t ULONGLONG
#endif

#ifndef uint32_t
#define uint32_t DWORD
#endif

#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory

#define INTEL_LAN_DRIVER_TIMESTAMP 0x5284EAC3
#define INTEL_LAN_DRIVER_IOCTL 0x80862007
#define INTEL_LAN_COPY_CASE_NUMBER 0x33

extern "C" NTSTATUS ZwQuerySystemInformation(
	ULONG InfoClass,
	PVOID Buffer,
	ULONG Length,
	PULONG ReturnLength
);

extern "C" NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID ImageBase,
	_In_ PCCH RoutineName
);

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	_OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[37];
	EX_PUSH_LOCK Lock;
	void* DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _COPY_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	void* source;
	void* destination;
	uint64_t length;
}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

typedef struct _FILL_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint32_t value;
	uint32_t reserved2;
	uint64_t destination;
	uint64_t length;
}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_physical_address;
	uint64_t address_to_translate;
}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

typedef struct _MAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_value;
	uint64_t return_virtual_address;
	uint64_t physical_address_to_map;
	uint32_t size;
}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t virt_address;
	uint64_t reserved3;
	uint32_t number_of_bytes;
}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

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

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
	USHORT e_magic;         // Magic number
	USHORT e_cblp;          // Bytes on last page of file
	USHORT e_cp;            // Pages in file
	USHORT e_crlc;          // Relocations
	USHORT e_cparhdr;       // Size of header in paragraphs
	USHORT e_minalloc;      // Minimum extra paragraphs needed
	USHORT e_maxalloc;      // Maximum extra paragraphs needed
	USHORT e_ss;            // Initial (relative) SS value
	USHORT e_sp;            // Initial SP value
	USHORT e_csum;          // Checksum
	USHORT e_ip;            // Initial IP value
	USHORT e_cs;            // Initial (relative) CS value
	USHORT e_lfarlc;        // File address of relocation table
	USHORT e_ovno;          // Overlay number
	USHORT e_res[4];        // Reserved words
	USHORT e_oemid;         // OEM identifier (for e_oeminfo)
	USHORT e_oeminfo;       // OEM information; e_oemid specific
	USHORT e_res2[10];      // Reserved words
	LONG   e_lfanew;        // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	short  Machine;
	short  NumberOfSections;
	unsigned TimeDateStamp;
	unsigned PointerToSymbolTable;
	unsigned NumberOfSymbols;
	short  SizeOfOptionalHeader;
	short  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned VirtualAddress;
	unsigned Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	short                 Magic;
	unsigned char                 MajorLinkerVersion;
	unsigned char                 MinorLinkerVersion;
	unsigned                SizeOfCode;
	unsigned                SizeOfInitializedData;
	unsigned                SizeOfUninitializedData;
	unsigned                AddressOfEntryPoint;
	unsigned                BaseOfCode;
	ULONGLONG            ImageBase;
	unsigned                SectionAlignment;
	unsigned                FileAlignment;
	short                 MajorOperatingSystemVersion;
	short                 MinorOperatingSystemVersion;
	short                 MajorImageVersion;
	short                 MinorImageVersion;
	short                 MajorSubsystemVersion;
	short                 MinorSubsystemVersion;
	unsigned                Win32VersionValue;
	unsigned                SizeOfImage;
	unsigned                SizeOfHeaders;
	unsigned                CheckSum;
	short                 Subsystem;
	short                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	unsigned                 LoaderFlags;
	unsigned                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	unsigned                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;                  // 0 if not bound,
											// -1 if bound, and real date\time stamp
											//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
											// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED* PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;  // PBYTE 
		ULONGLONG Function;         // PDWORD
		ULONGLONG Ordinal;
		ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA64, * PIMAGE_THUNK_DATA64;
typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;

typedef union _virt_addr_t
{
	void* value;
	struct
	{
		ULONG64 offset : 12;
		ULONG64 pt_index : 9;
		ULONG64 pd_index : 9;
		ULONG64 pdpt_index : 9;
		ULONG64 pml4_index : 9;
		ULONG64 reserved : 16;
	};
} virt_addr_t, * pvirt_addr_t;