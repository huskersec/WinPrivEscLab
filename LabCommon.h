#pragma once
// ============================================================================
// LabCommon.h
// Shared definitions for the WinPrivEscLab privilege escalation primitive suite.
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#pragma comment(lib, "ntdll.lib")

// ----------------------------------------------------------------------------
// Logging — prefixed so output is easy to grep per component
// ----------------------------------------------------------------------------
#define LAB_INFO(fmt, ...)  printf("[*] " fmt "\n", ##__VA_ARGS__)
#define LAB_OK(fmt, ...)    printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LAB_WARN(fmt, ...)  printf("[!] " fmt "\n", ##__VA_ARGS__)
#define LAB_ERR(fmt, ...)   printf("[-] " fmt "\n", ##__VA_ARGS__)
#define LAB_DBG(fmt, ...)   printf("    " fmt "\n", ##__VA_ARGS__)

// ----------------------------------------------------------------------------
// Canary struct written into every shared section by the vulnerable service.
//
// The exploit's proof-of-concept is overwriting WriterPid with its own PID,
// or flipping CanaryMagic — either demonstrates write access to a section
// owned by the SYSTEM process.
// ----------------------------------------------------------------------------
#define LAB_CANARY_MAGIC     0xDEADC0DEUl
#define LAB_CANARY_MAGIC_BAD 0xBADC0FFEUl   // written by attacker to signal compromise

#pragma pack(push, 1)
typedef struct _LAB_CANARY {
    ULONG   Magic;          // LAB_CANARY_MAGIC when healthy; LAB_CANARY_MAGIC_BAD if tampered
    ULONG   WriterPid;      // PID of the process that last wrote this struct
    ULONG   WriteCount;     // incremented each time the service refreshes
    WCHAR   WriterName[64]; // IMAGE_NAME of the writer process for display
} LAB_CANARY, *PLAB_CANARY;
#pragma pack(pop)

#define LAB_SECTION_SIZE  0x1000    // one page is sufficient for the canary

// ----------------------------------------------------------------------------
// P01_ObjSymlinkHijack operating modes — passed as the first argument to VulnLoader.exe
//
//   MODE_BLIND      No existence check before NtCreateSection (maximally vulnerable)
//   MODE_CHECKFIRST NtOpenDirectoryObject check before create (still vulnerable — TOCTOU)
//   MODE_OPENIF     Creates section with OBJ_OPENIF (symlink still followed)
// ----------------------------------------------------------------------------
#define VULNSVC_MODE_BLIND       0
#define VULNSVC_MODE_CHECKFIRST  1
#define VULNSVC_MODE_OPENIF      2

// ----------------------------------------------------------------------------
// NT native API declarations not in the SDK headers
// ----------------------------------------------------------------------------
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} LAB_OBJECT_ATTRIBUTES, *PLAB_OBJECT_ATTRIBUTES;

// Attribute flags
#define OBJ_CASE_INSENSITIVE    0x00000040UL
#define OBJ_OPENIF              0x00000080UL
#define OBJ_INHERIT             0x00000002UL

#define InitializeObjectAttributes(p, n, a, r, s) \
{                                                   \
    (p)->Length                   = sizeof(LAB_OBJECT_ATTRIBUTES); \
    (p)->RootDirectory            = r;              \
    (p)->Attributes               = a;              \
    (p)->ObjectName               = n;              \
    (p)->SecurityDescriptor       = s;              \
    (p)->SecurityQualityOfService = NULL;           \
}

// NtCreateSection / NtOpenSection
#define SECTION_ALL_ACCESS  0x000F001FL
#define SECTION_MAP_WRITE   0x00000002L
#define SECTION_MAP_READ    0x00000004L

typedef NTSTATUS (WINAPI *PFN_NtCreateSection)(
    OUT PHANDLE             SectionHandle,
    IN  ACCESS_MASK         DesiredAccess,
    IN  PLAB_OBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  PLARGE_INTEGER      MaximumSize         OPTIONAL,
    IN  ULONG               SectionPageProtection,
    IN  ULONG               AllocationAttributes,
    IN  HANDLE              FileHandle          OPTIONAL
);

typedef NTSTATUS (WINAPI *PFN_NtOpenSection)(
    OUT PHANDLE             SectionHandle,
    IN  ACCESS_MASK         DesiredAccess,
    IN  PLAB_OBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (WINAPI *PFN_NtMapViewOfSection)(
    IN  HANDLE              SectionHandle,
    IN  HANDLE              ProcessHandle,
    IN OUT PVOID*           BaseAddress,
    IN  ULONG_PTR           ZeroBits,
    IN  SIZE_T              CommitSize,
    IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
    IN OUT PSIZE_T          ViewSize,
    IN  ULONG               InheritDisposition,
    IN  ULONG               AllocationType,
    IN  ULONG               Win32Protect
);

typedef NTSTATUS (WINAPI *PFN_NtUnmapViewOfSection)(
    IN HANDLE ProcessHandle,
    IN PVOID  BaseAddress
);

typedef NTSTATUS (WINAPI *PFN_NtOpenDirectoryObject)(
    OUT PHANDLE             DirectoryHandle,
    IN  ACCESS_MASK         DesiredAccess,
    IN  PLAB_OBJECT_ATTRIBUTES ObjectAttributes
);

typedef VOID (WINAPI *PFN_RtlInitUnicodeString)(
    OUT PUNICODE_STRING DestinationString,
    IN  PCWSTR          SourceString OPTIONAL
);

// ViewUnmap / ViewShare for NtMapViewOfSection InheritDisposition
#define ViewShare  1
#define ViewUnmap  2

// NTSTATUS helpers
#define LAB_NT_SUCCESS(s)  ((NTSTATUS)(s) >= 0)

// ----------------------------------------------------------------------------
// Helper: load an NT function by name, abort loudly on failure
// ----------------------------------------------------------------------------
#define LAB_LOAD_NT(hMod, name, pfn)                                    \
    do {                                                                 \
        (pfn) = (decltype(pfn))GetProcAddress((hMod), #name);           \
        if (!(pfn)) {                                                    \
            LAB_ERR("GetProcAddress failed for %s (err %lu)", #name,    \
                    GetLastError());                                     \
            return FALSE;                                                \
        }                                                                \
    } while(0)

// ----------------------------------------------------------------------------
// Helper: format the section path used by primitive 01
//
//   \Sessions\<sessionId>\BaseNamedObjects\SimSvc.SharedCache<sessionId>
//
// Both P01_ObjSymlinkHijack and SimExploit use this same function so they always agree
// on the name without hardcoding it in two places.
// ----------------------------------------------------------------------------
inline void Lab01_BuildSectionPath(WCHAR* buf, SIZE_T cchBuf, DWORD sessionId)
{
    _snwprintf_s(buf, cchBuf, _TRUNCATE,
        L"\\Sessions\\%lu\\BaseNamedObjects\\SimSvc.SharedCache%lu",
        sessionId, sessionId);
}
