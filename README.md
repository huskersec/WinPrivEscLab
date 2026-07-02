# WinPrivEscLab

A self-contained Windows privilege-escalation research and training lab focused on **deep Windows internals** rather than checklist-style misconfiguration enumeration. It covers usermode and kernel-interface LPE primitives — Object Manager symlinks, registry/NTFS name resolution, section objects, handle inheritance, named-pipe/RPC/ALPC impersonation, and token/integrity abuse.

Deliberately distinct from HEVD: no vulnerable driver, no unquoted-service-path / weak-DACL / AlwaysInstallElevated filler. The point is to understand *why* the attack surface exists, not to enumerate misconfigurations.

## Philosophy

- **Understand before exploit** — foundation modules (F01–F04) explain the architecture before any exploit code appears.
- **Build both sides** — you write the intentionally vulnerable service *and* the exploit against it.
- **Progressive complexity** — primitives ordered by conceptual dependency; case studies (C01–C03) are synthesis exercises mapping real CVEs to practiced primitives.

## Architecture

**`VulnLoader.exe`** — single SYSTEM host/dispatcher, run via PsExec:

```
psexec -s -i 1 bin\VulnLoader.exe <primitive_id> [mode]
```

`-i 1` places SYSTEM in the interactive session so the session-scoped object namespace matches the attacker process. The first arg selects a primitive DLL; `[mode]` selects severity variant.

**Primitive modes** (consistent across all primitives):
- `0` — maximally vulnerable baseline (HIGH)
- `1` — partially mitigated, still exploitable (MEDIUM)
- `2` — correct/safe implementation, or variant technique

**`Common/LabCommon.h`** — shared NT native API typedefs, the `LAB_CANARY` proof-of-exploitation struct (written by SYSTEM, tampered by the attacker to prove cross-privilege write), path-construction helpers, `LAB_LOAD_NT` resolver macro, and logging macros.

**`SimExploit.exe`** — researcher-authored. READMEs give implementation hints, not full code.

## Layout

```
WinPrivEscLab/
├── build.bat                  Central build script
├── Common/LabCommon.h         Shared typedefs, canary, NT declarations
├── VulnLoader/VulnLoader.cpp  SYSTEM host / dispatcher
├── bin/                       Build output
│
├── F01–F04   Foundation: TOCTOU, Object Manager/handles, token/MIC model, IPC
├── H01–H02   Historical: window-shatter, NULL-page mapping
├── P01–P10   Primitives: symlink/junction/section/handle/pipe/RPC/ALPC/token
├── W01–W04   Weaponization: token→SYSTEM shell, section injection, SeDebug R/W
└── C01–C03   Case studies: PrintNightmare, Potato lineage, GreenPlasma
```

Each directory has a README: vulnerability class, what it teaches, operating modes, prerequisite concepts, and what it leads into.

## Status

- **P01 ObjectManagerSymlink** — `[BUILT]`, ready to build and test
- **P02–P10** — `[STUB]`
- Build order recommended next: F01–F03 demos → P02/P03/P04 (name-resolution trilogy) → P06/P07 (IPC) → W01–W04

## Build

Requires a Visual Studio Developer Command Prompt. From the repo root:

```
build.bat
```

Run P01:

```
psexec -s -i 1 bin\VulnLoader.exe P01        (mode 0 = BLIND)
psexec -s -i 1 bin\VulnLoader.exe P01 1      (mode 1 = CHECKFIRST)
psexec -s -i 1 bin\VulnLoader.exe P01 2      (mode 2 = OPENIF)
```

## Conceptual threads

- **Name Resolution Trust** (F01, F02, P01–P03, H01) — Object Manager → Registry → NTFS → Window Station, all variants of user-influenced namespace adjacent to privileged name resolution without atomicity.
- **IPC Boundary Trust** (F04, P06–P08) — Pipes → RPC → ALPC; privileged processes impersonating user-controlled endpoints. Potato family and PrintNightmare live here.
- **Shared State & Token Trust** (F03, P04, P05, P09, P10, W01–W04) — sections, handle inheritance, impersonation levels, integrity levels shared across privilege boundaries without validation.

## Tooling

WinObj, System Informer, NtObjectManager (Forshaw), PsExec. Static discovery via the `NamedObjectXrefFinder.java` and `TOCTOUPatternFinder.java` Ghidra scripts. Reference: *Windows Internals 7th Ed.* ch. 8–9.

> **Note:** Intentionally vulnerable code for research/training use in an isolated lab VM. Do not run on production systems.
