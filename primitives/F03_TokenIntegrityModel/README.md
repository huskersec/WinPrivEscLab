# F03 — Windows Token and Integrity Model

## Concept

Every process and thread in Windows runs in a security context defined by an
access token. The token determines what the process can access, what privileges
it holds, and at what integrity level it operates. Understanding tokens is
prerequisite to every IPC and weaponization primitive in this lab.

## Key Concepts

### Access Tokens
A token contains:
- User SID and group SIDs
- Privilege attributes (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
- Integrity level (Mandatory Integrity Control)
- Token type: Primary (process) or Impersonation (thread)
- Impersonation level (Identification, Impersonation, Delegation)

### Mandatory Integrity Control (MIC)
Introduced in Vista. Every object and subject has an integrity level:
- Low    (0x1000) — sandboxed processes (browser tabs, downloads)
- Medium (0x2000) — standard user processes
- High   (0x3000) — elevated/admin processes
- System (0x4000) — SYSTEM services

Write-up integrity policy: a lower-integrity process cannot write to a
higher-integrity object by default. This is the no-write-up rule.

### Primary vs Impersonation Tokens
- Primary token  — attached to a process, used for all operations unless
                   a thread overrides it
- Impersonation token — attached to a thread, temporarily overrides the
                        process token for that thread's operations

### Impersonation Levels
Determines what an impersonating server can do with the client's token:
- SecurityAnonymous      — server cannot identify the client
- SecurityIdentification — server can identify but not impersonate
- SecurityImpersonation  — server can impersonate on the local system
- SecurityDelegation     — server can impersonate across the network

Only SecurityImpersonation and SecurityDelegation allow the server to
actually act as the client. This distinction is central to P09.

### SeImpersonatePrivilege
Held by service accounts by default. Allows a process to impersonate any
client that connects to it. This is why service accounts are high-value
targets — if you can get a SYSTEM process to connect to your pipe or RPC
server, SeImpersonatePrivilege lets you capture and use that token.

## Demonstration

`TokenInspector.exe` — prints the current process token in full: user SID,
all group SIDs and their attributes, all privileges and their state, integrity
level, and token type/impersonation level. Run as a standard user, as admin,
and as SYSTEM to see the differences side by side.

## Prerequisites
None (runs standalone; context from F01/F02 helpful)

## Leads Into
P06 (Named Pipe Impersonation), P07 (RPC Process Creation), P09 (Token
Impersonation Level Confusion), P10 (MIC/COM), W01-W04 (all weaponization)
