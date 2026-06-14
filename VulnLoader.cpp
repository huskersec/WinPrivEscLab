// ============================================================================
// VulnLoader.cpp
// WinPrivEscLab — Central lab host / primitive dispatcher
//
// Usage:
//   psexec -s -i 1 VulnLoader.exe <primitive> [primitive-args...]
//
// Primitives:
//   P01  Object Manager Symbolic Link Hijack
//          VulnLoader.exe P01 [mode]   0=BLIND 1=CHECKFIRST 2=OPENIF
//   P02  Registry Symbolic Link Abuse
//          VulnLoader.exe P02 [mode]   0=BLIND 1=CHECKFIRST 2=VOLATILE
//   P03  NTFS Junction / Hardlink Attack
//          VulnLoader.exe P03 [mode]   0=JUNCTION 1=HARDLINK 2=OPLOCK
//   P04  Section Object Shared Memory Boundary
//          VulnLoader.exe P04 [mode]   0=READONLY 1=READWRITE 2=EXECUTE
//   P05  Handle Inheritance / DuplicateHandle Abuse
//          VulnLoader.exe P05 [mode]   0=INHERIT 1=DUPHANDLE 2=SECTION
//   P06  Named Pipe Token Impersonation
//          VulnLoader.exe P06 [mode]   0=SYSTEM_CONNECTS 1=IMPERSONATE 2=IDENTIFY
//   P07  RPC Process Creation Under Impersonation
//          VulnLoader.exe P07 [mode]   0=CREATEPROCESS 1=PATH_INFLUENCED 2=SAFE
//   P08  ALPC Interface Abuse
//          VulnLoader.exe P08 [mode]   0=IMPERSONATE 1=MSG_NOVALIDATE 2=WEAK_DACL
//   P09  Token Impersonation Level Confusion
//          VulnLoader.exe P09 [mode]   0=NO_CHECK 1=INVERTED_CHECK 2=SAFE
//   P10  MIC / COM Auto-Elevation Bypass
//          VulnLoader.exe P10 [mode]   0=FILE_METHOD 1=REG_METHOD 2=SAFE
//
// Build:
//   cl /W4 /WX /Zi /nologo VulnLoader.cpp /Fe:VulnLoader.exe /I..\..\Common
//      /link /SUBSYSTEM:CONSOLE
// ============================================================================

#include "..\..\Common\LabCommon.h"

// ----------------------------------------------------------------------------
// Dispatch function forward declarations — one per primitive.
// Implemented as stubs for unbuilt primitives; P01 is fully implemented.
// ----------------------------------------------------------------------------
static int Dispatch_P01(int argc, wchar_t** argv);
static int Dispatch_Stub(int argc, wchar_t** argv, const wchar_t* id);

// Stub shims — each just calls Dispatch_Stub with its own ID
static int Dispatch_P02(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P02"); }
static int Dispatch_P03(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P03"); }
static int Dispatch_P04(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P04"); }
static int Dispatch_P05(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P05"); }
static int Dispatch_P06(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P06"); }
static int Dispatch_P07(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P07"); }
static int Dispatch_P08(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P08"); }
static int Dispatch_P09(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P09"); }
static int Dispatch_P10(int argc, wchar_t** argv) { return Dispatch_Stub(argc, argv, L"P10"); }

// ----------------------------------------------------------------------------
// Primitive descriptor table
// Add a row here when a new primitive DLL is ready.
// ----------------------------------------------------------------------------
struct PrimitiveEntry
{
    const wchar_t* id;
    const wchar_t* name;
    const wchar_t* dll;
    const wchar_t* argHelp;
    int (*dispatch)(int, wchar_t**);
};

static const PrimitiveEntry g_Primitives[] =
{
    {
        L"P01",
        L"Object Manager Symbolic Link Hijack",
        L"P01_ObjSymlinkHijack.dll",
        L"  mode  0 = BLIND       no existence check (default)\n"
        L"        1 = CHECKFIRST  NtOpenDirectoryObject check then create\n"
        L"        2 = OPENIF      create with OBJ_OPENIF\n",
        Dispatch_P01
    },
    {
        L"P02",
        L"Registry Symbolic Link Abuse",
        L"P02_RegSymlinkHijack.dll",
        L"  mode  0 = BLIND       no check before key create (default)\n"
        L"        1 = CHECKFIRST  RegOpenKey check then create\n"
        L"        2 = VOLATILE    REG_OPTION_VOLATILE link\n",
        Dispatch_P02
    },
    {
        L"P03",
        L"NTFS Junction / Hardlink Attack",
        L"P03_NTFSJunctionHardlink.dll",
        L"  mode  0 = JUNCTION    privileged write through user junction\n"
        L"        1 = HARDLINK    privileged overwrite via hardlink\n"
        L"        2 = OPLOCK      oplock-assisted widened race window\n",
        Dispatch_P03
    },
    {
        L"P04",
        L"Section Object Shared Memory Boundary Violation",
        L"P04_SharedMemoryBoundary.dll",
        L"  mode  0 = READONLY    attacker proves read access\n"
        L"        1 = READWRITE   attacker overwrites command buffer\n"
        L"        2 = EXECUTE     section mapped executable\n",
        Dispatch_P04
    },
    {
        L"P05",
        L"Handle Inheritance / DuplicateHandle Abuse",
        L"P05_HandleInheritance.dll",
        L"  mode  0 = INHERIT     inheritable token handle leaked to child\n"
        L"        1 = DUPHANDLE   PROCESS_DUP_HANDLE granted to low-priv\n"
        L"        2 = SECTION     inheritable section handle with write access\n",
        Dispatch_P05
    },
    {
        L"P06",
        L"Named Pipe Token Impersonation",
        L"P06_NamedPipeImpersonation.dll",
        L"  mode  0 = SYSTEM_CONNECTS  SYSTEM service connects to attacker pipe\n"
        L"        1 = IMPERSONATE      client grants SecurityImpersonation\n"
        L"        2 = IDENTIFY         client grants SecurityIdentification only\n",
        Dispatch_P06
    },
    {
        L"P07",
        L"RPC Process Creation Under Impersonation",
        L"P07_RPCProcessCreation.dll",
        L"  mode  0 = CREATEPROCESS      CreateProcess under impersonation\n"
        L"        1 = PATH_INFLUENCED    executable path is user-influenced\n"
        L"        2 = SAFE               CreateProcessAsUser (correct, contrast)\n",
        Dispatch_P07
    },
    {
        L"P08",
        L"ALPC Interface Abuse",
        L"P08_ALPCAbuse.dll",
        L"  mode  0 = IMPERSONATE      server impersonates client insecurely\n"
        L"        1 = MSG_NOVALIDATE   message processed without validation\n"
        L"        2 = WEAK_DACL        port has weak security descriptor\n",
        Dispatch_P08
    },
    {
        L"P09",
        L"Token Impersonation Level Confusion",
        L"P09_TokenImpersonationLevel.dll",
        L"  mode  0 = NO_CHECK         uses token without checking level\n"
        L"        1 = INVERTED_CHECK   comparison is inverted (logic bug)\n"
        L"        2 = SAFE             correct level check (contrast)\n",
        Dispatch_P09
    },
    {
        L"P10",
        L"MIC / COM Auto-Elevation Bypass",
        L"P10_MICCOMAutoElevation.dll",
        L"  mode  0 = FILE_METHOD      auto-elevating COM, unsafe file method\n"
        L"        1 = REG_METHOD       auto-elevating COM, unsafe registry method\n"
        L"        2 = SAFE             correct elevation check (contrast)\n",
        Dispatch_P10
    },
};

static const DWORD g_PrimitiveCount = ARRAYSIZE(g_Primitives);

// ============================================================================
// Helpers
// ============================================================================

static void PrintBanner()
{
    LAB_INFO("=====================================================");
    LAB_INFO(" WinPrivEscLab — Windows Privilege Escalation Lab  ");
    LAB_INFO("=====================================================");
    LAB_INFO("  F01-F04  Foundation concepts");
    LAB_INFO("  H01-H02  Historical context primitives");
    LAB_INFO("  P01-P10  Core primitives  (this loader)");
    LAB_INFO("  W01-W04  Weaponization modules");
    LAB_INFO("  C01-C03  Case studies");
    LAB_INFO("=====================================================");
}

static void PrintUsage()
{
    LAB_INFO("Usage: VulnLoader.exe <primitive_id> [mode]");
    LAB_INFO("");
    LAB_INFO("Available primitives:");
    for (DWORD i = 0; i < g_PrimitiveCount; i++)
    {
        const PrimitiveEntry& p = g_Primitives[i];
        bool built = (p.dispatch != Dispatch_P02 &&
                      p.dispatch != Dispatch_P03 &&
                      p.dispatch != Dispatch_P04 &&
                      p.dispatch != Dispatch_P05 &&
                      p.dispatch != Dispatch_P06 &&
                      p.dispatch != Dispatch_P07 &&
                      p.dispatch != Dispatch_P08 &&
                      p.dispatch != Dispatch_P09 &&
                      p.dispatch != Dispatch_P10);

        wprintf(L"  %-5s  %-46s  [%s]\n",
            p.id, p.name, built ? L"BUILT" : L"STUB");

        // Print mode help, indented
        WCHAR tmp[512];
        wcsncpy_s(tmp, p.argHelp, _TRUNCATE);
        wchar_t* ctx = nullptr;
        wchar_t* line = wcstok_s(tmp, L"\n", &ctx);
        while (line) { wprintf(L"         %s\n", line); line = wcstok_s(nullptr, L"\n", &ctx); }
    }
    LAB_INFO("");
    LAB_INFO("Run as SYSTEM via: psexec -s -i 1 VulnLoader.exe <id> [mode]");
}

static void CheckSystemContext()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return;

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    BYTE* buf = (BYTE*)_alloca(dwSize);
    if (GetTokenInformation(hToken, TokenUser, buf, dwSize, &dwSize))
    {
        WCHAR name[64] = {}, domain[64] = {};
        DWORD cn = _countof(name), cd = _countof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, ((TOKEN_USER*)buf)->User.Sid,
                              name, &cn, domain, &cd, &use))
        {
            LAB_INFO("Running as  : %ls\\%ls", domain, name);
            if (_wcsicmp(name, L"SYSTEM") != 0)
                LAB_WARN("Not SYSTEM — use: psexec -s -i 1 VulnLoader.exe ...");
        }
    }
    CloseHandle(hToken);
}

static void PrintSessionInfo()
{
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    LAB_INFO("PID         : %lu", GetCurrentProcessId());
    LAB_INFO("Session ID  : %lu", sessionId);
    if (sessionId == 0)
        LAB_WARN("Session 0 — use psexec -i 1 to target the interactive session");
}

static HMODULE LoadPrimitiveDLL(const wchar_t* dllName)
{
    HMODULE h = LoadLibraryW(dllName);
    if (!h)
    {
        LAB_ERR("LoadLibrary(%ls) failed (%lu)", dllName, GetLastError());
        LAB_ERR("Ensure %ls is in the same directory as VulnLoader.exe", dllName);
    }
    return h;
}

// ============================================================================
// Stub dispatcher — used for primitives not yet built
// ============================================================================
static int Dispatch_Stub(int argc, wchar_t** argv, const wchar_t* id)
{
    LAB_WARN("Primitive %ls is not yet implemented.", id);
    LAB_WARN("See %ls\\README.md for the planned design.", id);
    return 1;
}

// ============================================================================
// P01 — Object Manager Symbolic Link Hijack (BUILT)
// ============================================================================
static int Dispatch_P01(int argc, wchar_t** argv)
{
    DWORD mode = VULNSVC_MODE_BLIND;
    if (argc >= 2) mode = (DWORD)_wtoi(argv[1]);
    if (mode > 2)
    {
        LAB_ERR("Invalid mode %lu for P01. Valid: 0=BLIND 1=CHECKFIRST 2=OPENIF", mode);
        return 1;
    }
    const wchar_t* modeNames[] = { L"BLIND", L"CHECKFIRST", L"OPENIF" };
    LAB_INFO("Primitive   : P01 — Object Manager Symbolic Link Hijack");
    LAB_INFO("Mode        : %lu (%ls)", mode, modeNames[mode]);

    WCHAR modeStr[8] = { 0 };
    _snwprintf_s(modeStr, _countof(modeStr), _TRUNCATE, L"%lu", mode);
    SetEnvironmentVariableW(L"VULNSVC_MODE", modeStr);

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    WCHAR sectionPath[MAX_PATH] = { 0 };
    Lab01_BuildSectionPath(sectionPath, _countof(sectionPath), sessionId);
    LAB_INFO("");
    LAB_INFO("Target section path (verify in WinObj after race window):");
    LAB_INFO("  %ls", sectionPath);
    LAB_INFO("");

    HMODULE hDll = LoadPrimitiveDLL(g_Primitives[0].dll);
    if (!hDll) return 1;
    LAB_OK("%ls loaded.", g_Primitives[0].dll);
    LAB_INFO("Press ENTER to unload and exit.");
    getchar();
    FreeLibrary(hDll);
    return 0;
}

// ============================================================================
// Entry point
// ============================================================================
int wmain(int argc, wchar_t** argv)
{
    PrintBanner();
    LAB_INFO("");
    CheckSystemContext();
    PrintSessionInfo();
    LAB_INFO("");

    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    const wchar_t* id = argv[1];
    for (DWORD i = 0; i < g_PrimitiveCount; i++)
    {
        if (_wcsicmp(id, g_Primitives[i].id) == 0)
            return g_Primitives[i].dispatch(argc - 1, argv + 1);
    }

    LAB_ERR("Unknown primitive: %ls", id);
    LAB_INFO("");
    PrintUsage();
    return 1;
}
