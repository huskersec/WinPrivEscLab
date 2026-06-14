# W04 — Cross-Process Memory Access via Debug Privilege

## Prerequisites
F02 (Object Namespace and Handle Model), F03 (Token and Integrity Model),
W03 (Token Privilege Manipulation)

## Weaponization Concept

With SeDebugPrivilege enabled, `OpenProcess` succeeds against any process
regardless of its DACL — including LSASS, SYSTEM services, and protected
processes (with some limitations). This enables reading and writing the
virtual memory of privileged processes.

## What SeDebugPrivilege Bypasses

Normal process open is gated by the target process object's DACL.
`SeDebugPrivilege` causes the object manager to skip the DACL check for
process and thread objects. The result: any process on the system can be
opened with `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`.

This is why SeDebugPrivilege is considered equivalent to SYSTEM — it
grants read/write access to every process's memory including LSASS.

## Key APIs

**OpenProcess** — with `SeDebugPrivilege` enabled, succeeds against any
non-PPL process with any desired access mask.

**ReadProcessMemory** — reads from another process's virtual address space.
Requires `PROCESS_VM_READ`.

**WriteProcessMemory** — writes to another process's virtual address space.
Requires `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION`.

**VirtualAllocEx / VirtualFreeEx** — allocate/free memory in another
process. Foundation of classic process injection.

**CreateRemoteThread** — create a thread in another process's context.
Classic injection completion step.

## Protected Processes and PPL

Standard `SeDebugPrivilege` does NOT bypass Protected Process (PP) or
Protected Process Light (PPL) restrictions. LSASS runs as PPL on modern
Windows by default. This module covers:
- How to check if a process is PP/PPL via `NtQueryInformationProcess`
- The boundary between what SeDebugPrivilege can and cannot access
- Why PPL was introduced specifically in response to LSASS memory reading

## What This Teaches

- The complete privilege-to-memory-access chain
- Virtual memory layout of a target process
- Why SeDebugPrivilege is treated as a security boundary in its own right
- Practical limits of cross-process memory access (PPL, CFG, ACG)
- How this technique underlies credential dumping tools (Mimikatz,
  Pypykatz) at a fundamental level

## Lab Exercise

Starting from a SYSTEM shell with SeDebugPrivilege enabled (W03):
1. Open the VulnLoader process with PROCESS_ALL_ACCESS
2. Enumerate memory regions via VirtualQueryEx
3. Read the LAB_CANARY struct from VulnLoader's mapped section view
4. Write to a non-critical memory region and verify the change
5. Observe the PPL check against a protected process

## Leads Into
C01 (PrintNightmare), C02 (Potato Lineage), C03 (GreenPlasma)
— all case studies assume fluency with the weaponization modules
