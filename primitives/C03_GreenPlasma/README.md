# C03 — GreenPlasma (2025)

## Prerequisites
F01 (TOCTOU), F02 (Object Namespace), F03 (Token and Integrity Model),
P01 (Object Manager Symlink), P02 (Registry Symbolic Link)

## Case Study Overview

GreenPlasma is the worked example this entire lab was built around. By the
time you reach this case study you will have studied every primitive it
uses. The goal here is to read the stripped PoC and reconstruct the complete
exploit chain from first principles, using what you have learned.

## The Chain — Mapped to Lab Primitives

```
F01  TOCTOU
  |
  +-> P01  Object Manager symlink planted in
  |        \Sessions\N\BaseNamedObjects\CTF.AsmListCache.FMPWinlogonN
  |        pointing to \BaseNamedObjects\CTFMON_DEAD (attacker-controlled)
  |
  +-> Trigger: ShellExecuteEx runas conhost.exe
  |   causes SYSTEM ctfmon to create the section through the symlink
  |
  +-> NtOpenSection poll — attacker acquires handle to SYSTEM-owned section
  |
  +-> P02  Registry symlink chain (SetPolicyVal)
  |        HKCU\Software\Policies\Microsoft\CloudFiles\BlockedApps
  |        -> \REGISTRY\USER\<SID>\...\Policies\System
  |        DisableLockWorkstation = 1
  |
  +-> Desktop synchronisation
  |   OpenInputDesktop loop detects Winlogon desktop transition
  |   LockWorkStation forces the transition
  |
  +-> [stripped — section content exploitation]
      SYSTEM ctfmon processes attacker-influenced section contents
```

## What Each Component Does

**The symlink (P01):** Intercepts ctfmon's section creation. The Object
Manager silently follows the symlink, creating the section at the attacker's
redirect target. The attacker now holds a MAXIMUM_ALLOWED handle to a
section owned by and shared with a SYSTEM process.

**The registry symlink (P02):** `SetPolicyVal` is not what triggers the
ctfmon vulnerability. Its purpose is to set `DisableLockWorkstation=1`
via a registry symlink chain, preventing the lock from invalidating the
desktop session state while the exploit completes.

**The desktop synchronisation:** `CTF.AsmListCache.FMPWinlogon` is
specifically instantiated when ctfmon services the Winlogon desktop context
(credential UI, lock screen). The `OpenInputDesktop` loop detects when
the active desktop transitions away from the user's default desktop. The
exploit synchronises to this transition because that is when the SYSTEM
ctfmon instance creates the target section.

**The stripped portion:** The section handle is the primitive. What the
original researcher did with it — the actual escalation — is the challenge
portion. Based on the lab primitives studied, the most likely approach
involves writing attacker-controlled data into the shared section that
the SYSTEM ctfmon process subsequently reads and processes, equivalent
to the P04/W02 chain.

## The Reconstruction Challenge

Armed with:
- The stripped PoC (GreenPlasma.cpp)
- Your SimExploit.exe implementation against P01
- Understanding of P02, P04, W02

Reconstruct what the stripped portion likely does by:
1. Statically analysing ctfmon.exe / msctf.dll for the section consumer
   (using the Ghidra scripts from the analysis session)
2. Identifying what ctfmon reads from the section after creation
3. Determining whether that read path is reachable from the section
   handle the attacker holds
4. Forming a hypothesis about the exploitation path

This is the capstone exercise for the entire lab.

## Win10 Absence

`CTF.AsmListCache.FMPWinlogonN` does not exist on Windows 10 — ctfmon
either does not create this object or names it differently. The vulnerability
is specific to the updated CTF subsystem in Windows 11 / Server 2022.
Differential analysis between Win10 and Win11 ctfmon/msctf using the
Ghidra scripts is the recommended approach for confirming this.

## Reference Material
- GreenPlasma GitHub (huskersec) — stripped PoC
- James Forshaw — CTF protocol vulnerability research (2019)
  "The CTF Protocol" — Project Zero blog series
- NtObjectManager PowerShell module — Forshaw
- Windows Internals 7th Edition — Chapter 8 (Object Manager),
  Chapter 9 (Processes and Threads — token model)
