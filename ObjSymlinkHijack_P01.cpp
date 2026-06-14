// ============================================================================
// ObjSymlinkHijack_P01.cpp
// WinPrivEscLab — Primitive 01: Object Manager Symbolic Link Hijack
//
// Simulates a privileged service (running as SYSTEM) that creates a named
// Section object in the session's BaseNamedObjects namespace without first
// verifying that no symbolic link already exists there.
//
// Operating modes (set via VULNSVC_MODE environment variable):
//   0 — BLIND      : NtCreateSection with no prior existence check (default)
//   1 — CHECKFIRST : NtOpenDirectoryObject check before create (still TOCTOU-vulnerable)
//   2 — OPENIF     : NtCreateSection with OBJ_OPENIF set (symlink still followed)
//
// Build:
//   cl /LD /W4 /WX /Zi /nologo ObjSymlinkHijack_P01.cpp /Fe:P01_ObjSymlinkHijack.dll /I..\..\Common
//      /link /SUBSYSTEM:CONSOLE ntdll.lib
// ============================================================================

#include "..\..\Common\LabCommon.h"
#include <tlhelp32.h>

// ----------------------------------------------------------------------------
// Globals
// ----------------------------------------------------------------------------
static PFN_NtCreateSection        g_NtCreateSection    = nullptr;
static PFN_NtOpenSection          g_NtOpenSection      = nullptr;
static PFN_NtMapViewOfSection     g_NtMapViewOfSection = nullptr;
static PFN_NtUnmapViewOfSection   g_NtUnmapViewOfSection = nullptr;
static PFN_NtOpenDirectoryObject  g_NtOpenDirectoryObject = nullptr;
static PFN_RtlInitUnicodeString   g_RtlInitUnicodeString = nullptr;

static HANDLE  g_hSection   = NULL;
static PVOID   g_pView      = NULL;
static HANDLE  g_hWorker    = NULL;
static BOOL    g_bRunning   = FALSE;
static DWORD   g_Mode       = VULNSVC_MODE_BLIND;

// ----------------------------------------------------------------------------
// Forward declarations
// ----------------------------------------------------------------------------
static BOOL  InitNtFunctions(void);
static BOOL  CreateVulnerableSection(DWORD sessionId);
static BOOL  CreateSection_Blind(const WCHAR* path);
static BOOL  CreateSection_CheckFirst(const WCHAR* path, DWORD sessionId);
static BOOL  CreateSection_OpenIf(const WCHAR* path);
static VOID  WriteCanary(DWORD writeCount);
static DWORD WINAPI WorkerThread(LPVOID lpParam);
static BOOL  GetProcessImageName(DWORD pid, WCHAR* buf, SIZE_T cchBuf);

// ============================================================================
// DLL entry point
// ============================================================================
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInst);

        // Read mode from environment — loader can set VULNSVC_MODE=0/1/2
        WCHAR modeStr[8] = { 0 };
        if (GetEnvironmentVariableW(L"VULNSVC_MODE", modeStr, _countof(modeStr)) > 0)
            g_Mode = (DWORD)_wtoi(modeStr);

        const char* modeNames[] = { "BLIND", "CHECKFIRST", "OPENIF" };
        LAB_INFO("P01_ObjSymlinkHijack loaded (mode %lu = %s)", g_Mode,
            g_Mode <= 2 ? modeNames[g_Mode] : "UNKNOWN");
        LAB_INFO("PID: %lu  |  Running as: %s",
            GetCurrentProcessId(),
            // Quick check — if we're SYSTEM the token user name contains "SYSTEM"
            []() -> const char* {
                HANDLE ht = NULL;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ht))
                    return "unknown";
                DWORD sz = 0;
                GetTokenInformation(ht, TokenUser, nullptr, 0, &sz);
                BYTE* buf = (BYTE*)_alloca(sz);
                GetTokenInformation(ht, TokenUser, buf, sz, &sz);
                WCHAR name[64] = {}, domain[64] = {};
                DWORD cName = 64, cDomain = 64;
                SID_NAME_USE use;
                LookupAccountSidW(nullptr,
                    ((TOKEN_USER*)buf)->User.Sid,
                    name, &cName, domain, &cDomain, &use);
                CloseHandle(ht);
                // Return a static — fine for this diagnostic lambda
                static char display[128];
                sprintf_s(display, "%ls\\%ls", domain, name);
                return display;
            }());

        if (!InitNtFunctions()) return FALSE;

        // Spawn the worker thread that creates and monitors the section
        g_bRunning = TRUE;
        g_hWorker  = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
        if (!g_hWorker)
        {
            LAB_ERR("CreateThread failed (%lu)", GetLastError());
            return FALSE;
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        g_bRunning = FALSE;
        if (g_hWorker)
        {
            WaitForSingleObject(g_hWorker, 3000);
            CloseHandle(g_hWorker);
        }
        if (g_pView && g_hSection)
            g_NtUnmapViewOfSection(GetCurrentProcess(), g_pView);
        if (g_hSection)
            CloseHandle(g_hSection);

        LAB_INFO("P01_ObjSymlinkHijack unloaded.");
    }
    return TRUE;
}

// ============================================================================
// Worker thread — creates the section then polls the canary
// ============================================================================
static DWORD WINAPI WorkerThread(LPVOID)
{
    DWORD sessionId = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId))
    {
        LAB_ERR("ProcessIdToSessionId failed (%lu)", GetLastError());
        return 1;
    }
    LAB_INFO("Session ID: %lu", sessionId);

    // -----------------------------------------------------------------------
    // Intentional delay — gives SimExploit.exe a window to plant its symlink.
    // In a real target this window would be the desktop-switch trigger.
    // -----------------------------------------------------------------------
    LAB_INFO("Waiting 5 seconds before creating section (race window open)...");
    LAB_WARN(">>> Plant your symlink now! <<<");
    Sleep(5000);

    if (!CreateVulnerableSection(sessionId))
    {
        LAB_ERR("Section creation failed — exiting worker.");
        return 1;
    }

    // -----------------------------------------------------------------------
    // Map a view so we can write/read the canary
    // -----------------------------------------------------------------------
    SIZE_T viewSize = LAB_SECTION_SIZE;
    LARGE_INTEGER offset = { 0 };
    NTSTATUS st = g_NtMapViewOfSection(
        g_hSection,
        GetCurrentProcess(),
        &g_pView,
        0, 0, &offset, &viewSize,
        ViewShare,
        0,
        PAGE_READWRITE);

    if (!LAB_NT_SUCCESS(st))
    {
        LAB_ERR("NtMapViewOfSection failed (0x%08X)", st);
        return 1;
    }
    LAB_OK("Section mapped at %p", g_pView);

    // -----------------------------------------------------------------------
    // Periodic canary write + tamper detection loop
    // -----------------------------------------------------------------------
    DWORD writeCount = 0;
    while (g_bRunning)
    {
        WriteCanary(++writeCount);

        Sleep(1000);

        // Read back and check
        PLAB_CANARY pCanary = (PLAB_CANARY)g_pView;
        if (pCanary->Magic == LAB_CANARY_MAGIC_BAD)
        {
            LAB_WARN("!!! CANARY TAMPERED !!!");
            LAB_WARN("    Magic    = 0x%08X (expected 0x%08X)",
                pCanary->Magic, LAB_CANARY_MAGIC);
            LAB_WARN("    WriterPid= %lu (our pid = %lu)",
                pCanary->WriterPid, GetCurrentProcessId());
            LAB_WARN("    Writer   = %ls", pCanary->WriterName);
            LAB_WARN("    This confirms the attacker holds a writable handle");
            LAB_WARN("    to this SYSTEM-owned section via symlink hijack.");
        }
        else if (pCanary->Magic == LAB_CANARY_MAGIC)
        {
            LAB_DBG("Canary OK  (write #%lu  pid=%lu)",
                pCanary->WriteCount, pCanary->WriterPid);
        }
        else
        {
            LAB_WARN("Canary has unexpected magic: 0x%08X", pCanary->Magic);
        }
    }
    return 0;
}

// ============================================================================
// Section creation — dispatches to the correct mode
// ============================================================================
static BOOL CreateVulnerableSection(DWORD sessionId)
{
    WCHAR path[MAX_PATH] = { 0 };
    Lab01_BuildSectionPath(path, _countof(path), sessionId);
    LAB_INFO("Target section path: %ls", path);

    switch (g_Mode)
    {
    case VULNSVC_MODE_BLIND:
        LAB_INFO("Mode: BLIND — creating section with no existence check");
        return CreateSection_Blind(path);

    case VULNSVC_MODE_CHECKFIRST:
        LAB_INFO("Mode: CHECKFIRST — NtOpenDirectoryObject check then create");
        return CreateSection_CheckFirst(path, sessionId);

    case VULNSVC_MODE_OPENIF:
        LAB_INFO("Mode: OPENIF — creating section with OBJ_OPENIF");
        return CreateSection_OpenIf(path);

    default:
        LAB_ERR("Unknown mode %lu", g_Mode);
        return FALSE;
    }
}

// ----------------------------------------------------------------------------
// Mode 0: BLIND — the maximally vulnerable case
//   NtCreateSection with no prior check; if a symlink exists at the path,
//   the Object Manager follows it silently and the section is created at the
//   redirect target (which the attacker controls).
// ----------------------------------------------------------------------------
static BOOL CreateSection_Blind(const WCHAR* path)
{
    UNICODE_STRING uPath = { 0 };
    g_RtlInitUnicodeString(&uPath, path);

    LAB_OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    LARGE_INTEGER size = { 0 };
    size.QuadPart = LAB_SECTION_SIZE;

    NTSTATUS st = g_NtCreateSection(
        &g_hSection,
        SECTION_ALL_ACCESS,
        &oa,
        &size,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);

    if (!LAB_NT_SUCCESS(st))
    {
        LAB_ERR("NtCreateSection(BLIND) failed (0x%08X)", st);
        return FALSE;
    }

    LAB_OK("Section created (BLIND)  handle=0x%p", g_hSection);
    LAB_INFO("Check WinObj/System Informer — if the section appears at the");
    LAB_INFO("attacker's redirect target rather than here, the hijack worked.");
    return TRUE;
}

// ----------------------------------------------------------------------------
// Mode 1: CHECKFIRST — existence check before create
//   Tries to open the parent directory and query for the object name first.
//   This is STILL vulnerable because the check and the create are not atomic.
//   The attacker can plant the symlink after the check and before the create.
//   Demonstrates why a non-atomic check-then-act is insufficient.
// ----------------------------------------------------------------------------
static BOOL CreateSection_CheckFirst(const WCHAR* path, DWORD sessionId)
{
    // Build the directory path for this session's BaseNamedObjects
    WCHAR dirPath[MAX_PATH] = { 0 };
    _snwprintf_s(dirPath, _countof(dirPath), _TRUNCATE,
        L"\\Sessions\\%lu\\BaseNamedObjects", sessionId);

    UNICODE_STRING uDir = { 0 };
    g_RtlInitUnicodeString(&uDir, dirPath);

    LAB_OBJECT_ATTRIBUTES oaDir = { 0 };
    InitializeObjectAttributes(&oaDir, &uDir, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    NTSTATUS st = g_NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oaDir);
    if (!LAB_NT_SUCCESS(st))
    {
        LAB_WARN("NtOpenDirectoryObject failed (0x%08X) — skipping check", st);
    }
    else
    {
        LAB_INFO("Directory opened OK — pretending to check for pre-existing object...");
        // In a real implementation you would call NtQueryDirectoryObject here.
        // For the lab we just simulate the check passing (object not found).
        // The race window is between this CloseHandle and the NtCreateSection below.
        CloseHandle(hDir);

        // Artificial delay to make the race window observable in the lab.
        // Remove this to make Mode 1 behave like a real (still racy) service.
        LAB_WARN(">>> [Mode 1] TOCTOU window open — plant symlink NOW <<<");
        Sleep(3000);
    }

    // Proceeds to create regardless — same as BLIND from here
    return CreateSection_Blind(path);
}

// ----------------------------------------------------------------------------
// Mode 2: OPENIF — creates with OBJ_OPENIF
//   OBJ_OPENIF means "open if it already exists, create otherwise."
//   Importantly, if a symlink exists at the path, NtCreateSection still
//   follows it during name resolution BEFORE deciding to open-or-create.
//   So the attacker's redirect is still honoured — the section ends up at
//   the attacker's target, just like in BLIND mode.
// ----------------------------------------------------------------------------
static BOOL CreateSection_OpenIf(const WCHAR* path)
{
    UNICODE_STRING uPath = { 0 };
    g_RtlInitUnicodeString(&uPath, path);

    LAB_OBJECT_ATTRIBUTES oa = { 0 };
    // OBJ_OPENIF — the only difference from BLIND
    InitializeObjectAttributes(&oa, &uPath,
        OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    LARGE_INTEGER size = { 0 };
    size.QuadPart = LAB_SECTION_SIZE;

    NTSTATUS st = g_NtCreateSection(
        &g_hSection,
        SECTION_ALL_ACCESS,
        &oa,
        &size,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);

    if (!LAB_NT_SUCCESS(st))
    {
        LAB_ERR("NtCreateSection(OPENIF) failed (0x%08X)", st);
        return FALSE;
    }

    LAB_OK("Section created (OPENIF)  handle=0x%p", g_hSection);
    LAB_INFO("OBJ_OPENIF does NOT prevent symlink following — same as BLIND.");
    return TRUE;
}

// ============================================================================
// Canary write
// ============================================================================
static VOID WriteCanary(DWORD writeCount)
{
    if (!g_pView) return;
    PLAB_CANARY pCanary = (PLAB_CANARY)g_pView;

    pCanary->Magic      = LAB_CANARY_MAGIC;
    pCanary->WriterPid  = GetCurrentProcessId();
    pCanary->WriteCount = writeCount;

    GetProcessImageName(GetCurrentProcessId(),
        pCanary->WriterName, _countof(pCanary->WriterName));
}

static BOOL GetProcessImageName(DWORD pid, WCHAR* buf, SIZE_T cchBuf)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe))
    {
        do {
            if (pe.th32ProcessID == pid)
            {
                wcsncpy_s(buf, cchBuf, pe.szExeFile, _TRUNCATE);
                CloseHandle(hSnap);
                return TRUE;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return FALSE;
}

// ============================================================================
// NT function resolution
// ============================================================================
static BOOL InitNtFunctions(void)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        LAB_ERR("GetModuleHandle(ntdll) failed");
        return FALSE;
    }

    LAB_LOAD_NT(hNtdll, NtCreateSection,       g_NtCreateSection);
    LAB_LOAD_NT(hNtdll, NtOpenSection,         g_NtOpenSection);
    LAB_LOAD_NT(hNtdll, NtMapViewOfSection,    g_NtMapViewOfSection);
    LAB_LOAD_NT(hNtdll, NtUnmapViewOfSection,  g_NtUnmapViewOfSection);
    LAB_LOAD_NT(hNtdll, NtOpenDirectoryObject, g_NtOpenDirectoryObject);
    LAB_LOAD_NT(hNtdll, RtlInitUnicodeString,  g_RtlInitUnicodeString);

    LAB_OK("NT functions resolved.");
    return TRUE;
}
