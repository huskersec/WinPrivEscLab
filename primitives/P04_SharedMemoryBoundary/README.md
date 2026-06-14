# P04 — Section Object Shared Memory Privilege Boundary Violation

## Prerequisites
F01 (TOCTOU), F02 (Object Namespace), P01 (Object Manager Symlink)

## Vulnerability Class

A direct extension of P01. Once a symlink hijack yields a handle to a
SYSTEM-owned section object, the attacker holds bidirectional shared memory
with a privileged process. This primitive explores what can be done with
that access.

The vulnerability class is "trusted reader of untrusted shared memory" —
a SYSTEM process maps a section and reads data from it, trusting the contents
to be well-formed. An attacker with a handle to the same section can write
arbitrary data into the shared mapping, causing the SYSTEM process to process
attacker-controlled input.

## What This Teaches

- Section object permissions — `SECTION_MAP_READ`, `SECTION_MAP_WRITE`,
  `SECTION_MAP_EXECUTE`
- `NtMapViewOfSection` — how both processes map views of the same physical
  pages
- Write primitive → what a SYSTEM process might do with shared data
  (IPC messages, configuration structs, command buffers)
- Why shared memory IPC requires the same input validation discipline as
  network input — the sender cannot be trusted

## Canary Overwrite as Proof

The canary struct from P01 (`LAB_CANARY`) is the simplest demonstration.
Extended in P04 to include a command buffer that the SYSTEM process "executes"
— showing how shared memory write access translates to behavioral influence
over the privileged process.

## Modes

| Mode | Description                                              | Severity |
|------|----------------------------------------------------------|----------|
| 0    | Read-only section — attacker proves read access          | MEDIUM   |
| 1    | Read-write section — attacker overwrites command buffer  | HIGH     |
| 2    | Execute section — section mapped executable              | CRITICAL |

## Lab Component
`P04_SharedMemoryBoundary.dll` loaded via `VulnLoader.exe 04 [mode]`

## Leads Into
W02 (Shared Memory Injection — weaponisation of this primitive)
