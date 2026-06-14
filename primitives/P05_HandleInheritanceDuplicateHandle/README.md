# P05 — Handle Inheritance and DuplicateHandle Abuse

## Prerequisites
F02 (Object Namespace and Handle Model), F03 (Token and Integrity Model)

## Vulnerability Class

One of the oldest Windows privilege escalation primitives — present since
Windows XP. Two related patterns:

**Handle Inheritance** — when a process is created with `bInheritHandles=TRUE`,
all inheritable handles from the parent are copied into the child's handle
table with the same access rights. If a privileged parent creates a child
process and passes inheritable handles it didn't intend to share, the child
(potentially attacker-controlled) can use them to access privileged resources.

**DuplicateHandle Abuse** — `DuplicateHandle` copies a handle from one process
to another. To duplicate a handle FROM another process you need
`PROCESS_DUP_HANDLE` access to the source process. This access right is
sometimes granted too broadly — if a lower-privileged process has
`PROCESS_DUP_HANDLE` on a SYSTEM process, it can duplicate any of that
process's handles including tokens, section objects, and process handles.

## What This Teaches

- The Windows handle table — per-process, access rights fixed at open time
- Handle inheritance flags — `HANDLE_FLAG_INHERIT`
- `DuplicateHandle` semantics and required access rights
- Why `PROCESS_DUP_HANDLE` is a dangerous access right
- Handle scanning via `NtQuerySystemInformation(SystemHandleInformation)`
  to find inherited or accessible handles across processes

## The Cross-Process Handle Scan

A foundational technique: enumerate all handles system-wide, filter by
object type and access rights, identify handles in high-privilege processes
that the current process can duplicate. This is the discovery step that
precedes DuplicateHandle abuse and is worth understanding as a standalone
skill.

## Modes

| Mode | Description                                              | Severity |
|------|----------------------------------------------------------|----------|
| 0    | Inheritable token handle leaked to child process         | HIGH     |
| 1    | PROCESS_DUP_HANDLE granted to low-priv process           | HIGH     |
| 2    | Inheritable section handle with write access leaked      | HIGH     |

## Lab Component
`P05_HandleInheritance.dll` loaded via `VulnLoader.exe 05 [mode]`

## Leads Into
W01 (Token Impersonation to SYSTEM — token handle is the starting point),
W04 (Debug Privilege Cross-Process Memory Access)
