# P10 — Mandatory Integrity Control / COM Auto-Elevation Bypass

## Prerequisites
F03 (Token and Integrity Model), P09 (Token Impersonation Level Confusion)

## Vulnerability Class

Vista introduced Mandatory Integrity Control (MIC) and UAC. Auto-elevation
is a UAC mechanism that allows specific whitelisted COM objects and executables
to elevate to High integrity without prompting the user. The vulnerability
class exploits how the auto-elevation whitelist is evaluated and how COM
object activation crosses integrity boundaries.

Two related patterns:

**COM Auto-Elevation Object Abuse**
Certain COM CLSIDs are registered for auto-elevation in HKLM and will be
instantiated at High integrity when requested by a Medium integrity caller.
If such a COM object exposes a method that performs a privileged file or
registry operation on behalf of the caller, a Medium integrity process can
use it to write to locations normally requiring High integrity.
`IFileOperation` via the shell's elevated COM surrogate is the canonical
historical example.

**IFileOperation / IShdocvw Elevation**
The shell's file operation COM object, when instantiated through the elevated
surrogate, performs file copies and moves as a High integrity process. A
Medium integrity caller can use it to copy files to protected directories
such as `C:\Windows\System32` — normally write-protected against Medium
integrity processes.

## What This Teaches

- MIC no-write-up policy and how COM activation interacts with it
- `CoCreateInstance` with `CLSCTX_LOCAL_SERVER` — COM surrogate process
- How to identify auto-elevation candidates —
  HKLM COM registrations with `AutoElevate=1` in their manifest
- Process integrity level of the surrogate vs the caller
- Why whitelisting is a fragile mitigation — every auto-elevated object
  is an implicit elevation surface

## Historical Significance

The UAC bypass research era (2009-2015) produced dozens of techniques against
auto-elevated COM objects. Microsoft's response was to progressively narrow
the whitelist and add manifest checks. Understanding this cat-and-mouse history
explains why the modern UAC bypass surface is smaller but never eliminated —
the fundamental design (some COM objects must auto-elevate) creates permanent
attack surface.

## Modes

| Mode | Description                                                  | Severity |
|------|--------------------------------------------------------------|----------|
| 0    | Simulated auto-elevating COM object with unsafe file method  | HIGH     |
| 1    | Auto-elevating COM object with unsafe registry method        | HIGH     |
| 2    | Correctly implemented elevation check — for contrast         | NONE     |

## Lab Component
`P10_MICCOMAutoElevation.dll` loaded via `VulnLoader.exe 10 [mode]`

## Leads Into
W01 (Token Impersonation to SYSTEM), W03 (Token Privilege Manipulation),
C02 (Potato Lineage — integrity level constraints on impersonation)
