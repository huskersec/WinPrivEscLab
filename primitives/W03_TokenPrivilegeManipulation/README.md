# W03 — Token Privilege Manipulation

## Prerequisites
F03 (Token and Integrity Model), W01 (Token Impersonation to SYSTEM)

## Weaponization Concept

Once a SYSTEM token has been acquired, specific privileges within it
determine what further capabilities are available. This module teaches
which privileges matter, how to enable them, and what each enables in
an attack chain.

## Key Privileges

**SeDebugPrivilege**
Allows `OpenProcess` with `PROCESS_ALL_ACCESS` against any process
regardless of DACL. The single most powerful privilege for post-escalation
work. Enables W04 (cross-process memory access), process injection, and
reading LSASS memory. Held by administrators but not standard users.

**SeImpersonatePrivilege**
Allows a process to impersonate any client that connects to it at
SecurityImpersonation level or higher. Required for W01. Held by service
accounts by default — the reason service account compromise reliably leads
to SYSTEM.

**SeAssignPrimaryTokenPrivilege**
Allows assigning a primary token to a process via `CreateProcessAsUser`.
Typically held only by SYSTEM. Required for some token-to-process chains
where `CreateProcessWithTokenW` is not available.

**SeCreateTokenPrivilege**
Allows creating an arbitrary token via `NtCreateToken`. The nuclear option
— with this privilege an attacker can fabricate a token with any SIDs and
privileges. Held only by LSASS in normal configurations.

**SeTakeOwnershipPrivilege**
Allows taking ownership of any object regardless of DACL. Enables writing
to protected registry keys and files by first taking ownership then
modifying the DACL.

**SeRestorePrivilege**
Allows writing to any file regardless of DACL when opened with
`FILE_FLAG_BACKUP_SEMANTICS`. Commonly used for registry hive injection.

## AdjustTokenPrivileges

Privileges are present in a token in one of three states:
- Disabled (present but inactive — most privileges start here)
- Enabled (active)
- Removed (cannot be re-enabled)

`AdjustTokenPrivileges` enables disabled privileges. You cannot add
privileges that are not already present in the token — you can only
enable what is there.

## What This Teaches

- Enumerating token privileges via `GetTokenInformation(TokenPrivileges)`
- Enabling specific privileges with `AdjustTokenPrivileges`
- Which privileges are present on service accounts vs standard users
- Why privilege stripping (removing rather than just disabling) is a
  meaningful security hardening step
- The interaction between integrity level and privilege availability

## Lab Exercise

Starting from a SYSTEM process spawned in W01:
1. Enumerate all privileges in the current token
2. Enable SeDebugPrivilege
3. Verify by opening a protected process with PROCESS_ALL_ACCESS
4. Demonstrate SeTakeOwnershipPrivilege against a protected registry key

## Leads Into
W04 (Debug Privilege Cross-Process Memory Access)
