@echo off
:: ============================================================================
:: WinPrivEscLab — build.bat
:: Builds VulnLoader.exe and all implemented primitive DLLs.
:: Run from a Visual Studio Developer Command Prompt.
::
:: Output: all binaries land in bin\
::
:: Primitive DLL naming: P##_<ShortName>.dll
:: ============================================================================

setlocal
set ROOT=%~dp0
set BIN=%ROOT%bin
set COMMON=%ROOT%Common

if not exist "%BIN%" mkdir "%BIN%"

:: ----------------------------------------------------------------------------
:: VulnLoader.exe — central dispatcher, always built
:: ----------------------------------------------------------------------------
echo [*] Building VulnLoader.exe...
cl /W4 /WX /Zi /nologo ^
    "%ROOT%VulnLoader\VulnLoader.cpp" ^
    /Fe:"%BIN%\VulnLoader.exe" ^
    /Fd:"%BIN%\VulnLoader.pdb" ^
    /I"%COMMON%" ^
    /link /SUBSYSTEM:CONSOLE
if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P01 — Object Manager Symbolic Link Hijack  [BUILT]
:: ----------------------------------------------------------------------------
echo [*] Building P01_ObjSymlinkHijack.dll...
cl /LD /W4 /WX /Zi /nologo ^
    "%ROOT%P01_ObjectManagerSymlink\VulnSvc\ObjSymlinkHijack_P01.cpp" ^
    /Fe:"%BIN%\P01_ObjSymlinkHijack.dll" ^
    /Fd:"%BIN%\P01_ObjSymlinkHijack.pdb" ^
    /I"%COMMON%" ^
    /link ntdll.lib tlhelp32.lib ^
    /SUBSYSTEM:CONSOLE
if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P02 — Registry Symbolic Link Abuse  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P02_RegSymlinkHijack.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P02_RegistrySymlink\VulnSvc\RegSymlinkHijack_P02.cpp" ^
::     /Fe:"%BIN%\P02_RegSymlinkHijack.dll" ^
::     /Fd:"%BIN%\P02_RegSymlinkHijack.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib advapi32.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P03 — NTFS Junction / Hardlink Attack  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P03_NTFSJunctionHardlink.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P03_NTFSJunctionHardlink\VulnSvc\NTFSJunctionHardlink_P03.cpp" ^
::     /Fe:"%BIN%\P03_NTFSJunctionHardlink.dll" ^
::     /Fd:"%BIN%\P03_NTFSJunctionHardlink.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P04 — Section Object Shared Memory Boundary  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P04_SharedMemoryBoundary.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P04_SharedMemoryBoundary\VulnSvc\SharedMemoryBoundary_P04.cpp" ^
::     /Fe:"%BIN%\P04_SharedMemoryBoundary.dll" ^
::     /Fd:"%BIN%\P04_SharedMemoryBoundary.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P05 — Handle Inheritance / DuplicateHandle  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P05_HandleInheritance.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P05_HandleInheritanceDuplicateHandle\VulnSvc\HandleInheritance_P05.cpp" ^
::     /Fe:"%BIN%\P05_HandleInheritance.dll" ^
::     /Fd:"%BIN%\P05_HandleInheritance.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P06 — Named Pipe Token Impersonation  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P06_NamedPipeImpersonation.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P06_NamedPipeImpersonation\VulnSvc\NamedPipeImpersonation_P06.cpp" ^
::     /Fe:"%BIN%\P06_NamedPipeImpersonation.dll" ^
::     /Fd:"%BIN%\P06_NamedPipeImpersonation.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P07 — RPC Process Creation Under Impersonation  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P07_RPCProcessCreation.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P07_RPCProcessCreationImpersonation\VulnSvc\RPCProcessCreation_P07.cpp" ^
::     /Fe:"%BIN%\P07_RPCProcessCreation.dll" ^
::     /Fd:"%BIN%\P07_RPCProcessCreation.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib rpcrt4.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P08 — ALPC Interface Abuse  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P08_ALPCAbuse.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P08_ALPCAbuse\VulnSvc\ALPCAbuse_P08.cpp" ^
::     /Fe:"%BIN%\P08_ALPCAbuse.dll" ^
::     /Fd:"%BIN%\P08_ALPCAbuse.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P09 — Token Impersonation Level Confusion  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P09_TokenImpersonationLevel.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P09_TokenImpersonationLevelConfusion\VulnSvc\TokenImpersonationLevel_P09.cpp" ^
::     /Fe:"%BIN%\P09_TokenImpersonationLevel.dll" ^
::     /Fd:"%BIN%\P09_TokenImpersonationLevel.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

:: ----------------------------------------------------------------------------
:: P10 — MIC / COM Auto-Elevation Bypass  [STUB]
:: ----------------------------------------------------------------------------
:: echo [*] Building P10_MICCOMAutoElevation.dll...
:: cl /LD /W4 /WX /Zi /nologo ^
::     "%ROOT%P10_MICCOMAutoElevation\VulnSvc\MICCOMAutoElevation_P10.cpp" ^
::     /Fe:"%BIN%\P10_MICCOMAutoElevation.dll" ^
::     /Fd:"%BIN%\P10_MICCOMAutoElevation.pdb" ^
::     /I"%COMMON%" ^
::     /link ntdll.lib ole32.lib ^
::     /SUBSYSTEM:CONSOLE
:: if errorlevel 1 goto fail

echo.
echo [+] Build complete. Binaries in: %BIN%
echo.
echo [*] Usage examples:
echo     psexec -s -i 1 "%BIN%\VulnLoader.exe" P01
echo     psexec -s -i 1 "%BIN%\VulnLoader.exe" P01 1
echo     psexec -s -i 1 "%BIN%\VulnLoader.exe" P01 2
echo.
echo [*] Stub primitives: P02-P10 (uncomment build block when implemented)
goto end

:fail
echo.
echo [-] Build failed.
exit /b 1

:end
endlocal
