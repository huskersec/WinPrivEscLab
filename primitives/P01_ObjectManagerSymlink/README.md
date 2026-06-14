# Primitive 01 — Object Manager Symbolic Link Hijack

## Vulnerability Class

A privileged process (SYSTEM) creates a named kernel object in the session's
`BaseNamedObjects` namespace without first verifying that no symbolic link
already exists at that path. Because low-privileged users can create objects
in their own session's `BaseNamedObjects`, an attacker can pre-plant a symlink
that redirects the SYSTEM create to an attacker-controlled location, resulting
in the attacker holding a handle to an object created by and shared with the
SYSTEM process.

Real-world example: GreenPlasma (2025) — `CTF.AsmListCache.FMPWinlogon<N>`
in ctfmon.exe / msctf.dll.

---

## Repo Layout

```
WinPrivEscLab/
├── build.bat
├── Common/
│   └── LabCommon.h                  shared typedefs, canary struct, NT decls
├── VulnLoader/
│   └── VulnLoader.cpp               central dispatcher — runs as SYSTEM
├── bin/                             all build output lands here
│   ├── VulnLoader.exe
│   ├── P01_ObjSymlinkHijack.dll
│   └── P02_RegSymlinkBypass.dll               (future)
├── P01_ObjectManagerSymlink/
│   ├── README.md                    (this file)
│   └── P01_ObjSymlinkHijack/
│       └── ObjSymlinkHijack_P01.cpp
└── 02_*/                            (future primitives)
```

## Components

| Component          | Role                                                              |
|--------------------|-------------------------------------------------------------------|
| `VulnLoader.exe`   | Central host — dispatches to primitives via `01`, `02`, ... args  |
| `P01_ObjSymlinkHijack.dll`   | Primitive 01 — simulated vulnerable SYSTEM service                |
| `SimExploit.exe`   | **Written by you** — plants symlink, acquires handle, proves access |

---

## Lab Setup

### Requirements
- Windows 10/11 or Server 2019/2022 VM
- PsExec (Sysinternals) on PATH
- WinObj or System Informer for verification
- WinDbg attached (optional but recommended)

### Build
From a Visual Studio Developer Command Prompt at the repo root:
```
build.bat
```

### Running the Lab

**Terminal 1 — SYSTEM context (run as Administrator):**
```
psexec -s -i 1 bin\VulnLoader.exe 01 [mode]
```
Mode: `0` = BLIND (default), `1` = CHECKFIRST, `2` = OPENIF

**Terminal 2 — unprivileged user:**
```
bin\SimExploit.exe
```

VulnLoader prints the expected section path and announces a 5-second race
window. You have that window to plant your symlink from SimExploit.

---

## Operating Modes

### Mode 0 — BLIND (HIGH severity)
`NtCreateSection` is called with no prior existence check. The maximally
vulnerable case. If a symlink exists at the path the Object Manager follows
it silently and the section is created at the attacker's redirect target.

### Mode 1 — CHECKFIRST (MEDIUM severity)
`NtOpenDirectoryObject` is called before the create to simulate a "safe"
existence check. Still TOCTOU-vulnerable — the check and the create are not
atomic. An artificial 3-second delay makes the window observable in the lab.

### Mode 2 — OPENIF (MEDIUM severity)
`NtCreateSection` called with `OBJ_OPENIF` in ObjectAttributes. The symlink
is followed during name resolution *before* the open-or-create decision —
redirect still lands at the attacker's target, same as BLIND.

---

## Verification Steps

1. Run VulnLoader and note the section path printed to console
2. Open WinObj → `\Sessions\1\BaseNamedObjects\`
3. Before SimExploit: confirm the section does NOT exist yet
4. Run SimExploit — plant the symlink
5. After race window closes: confirm in WinObj the section now lives at
   your redirect target (`\BaseNamedObjects\SimAttacker.Section`)
6. Watch VulnLoader console — prints `CANARY TAMPERED` when SimExploit
   overwrites the canary magic value

---

## SimExploit.exe — Implementation Hints

Work through these steps in order. Verify each in WinObj or console output
before proceeding to the next.

**Step 1** — Get your session ID via `ProcessIdToSessionId`

**Step 2** — Call `Lab01_BuildSectionPath` from `LabCommon.h` to construct
the target path — guarantees you match P01_ObjSymlinkHijack exactly

**Step 3** — Create your real section at `\BaseNamedObjects\SimAttacker.Section`
directly via `NtCreateSection` (not through the symlink path)

**Step 4** — Plant the Object Manager symlink at the P01_ObjSymlinkHijack path pointing to
your real section via `NtCreateSymbolicLinkObject`

**Step 5** — Poll `NtOpenSection` on the symlink path until it resolves
(P01_ObjSymlinkHijack has run, followed your redirect, the section exists at your target)

**Step 6** — Map the view with `NtMapViewOfSection` and read the canary —
confirm Magic == `LAB_CANARY_MAGIC` and WriterPid == VulnLoader's PID

**Step 7** — Overwrite `Magic` with `LAB_CANARY_MAGIC_BAD` and `WriterPid`
with your own PID — watch VulnLoader console react

---

## WinDbg Observation (optional but valuable)

Break on `ObpLookupObjectName` in the SYSTEM process and watch the symlink
resolution happen live:

```
bp nt!ObpLookupObjectName
```

You can observe the Object Manager traverse the directory, find your symlink,
and redirect name resolution to the attacker-controlled namespace.

---

## Primitive Summary

| Property               | Value                                               |
|------------------------|-----------------------------------------------------|
| Requires admin?        | No                                                  |
| Session constraint     | Attacker and target must share a session            |
| Race window            | Between directory traversal and object creation     |
| Defeated by            | Atomic create-exclusive with pre-existence check    |
| Partially mitigated by | OBJ_OPENIF (not fully — symlink still followed)     |
| Detection              | ETW object manager events, handle auditing          |
