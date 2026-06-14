# P06 — Named Pipe Token Impersonation

## Prerequisites
F03 (Token and Integrity Model), F04 (IPC Mechanisms)

## Vulnerability Class

A named pipe server calls `ImpersonateNamedPipeClient` after a client connects,
temporarily assuming the client's security context on the calling thread. If
the server is a low-privileged attacker and the client is a SYSTEM process,
the attacker captures a SYSTEM impersonation token.

The vulnerability requires a privileged process to connect to an
attacker-controlled pipe. This happens more often than expected:
- Services that resolve pipe names through user-influenced paths
- COM servers that create pipes with predictable names
- Processes that connect to pipes based on registry configuration
- The SYSTEM process connecting to trigger the escalation
  (classic Potato-family technique)

## What This Teaches

- Named pipe creation — `CreateNamedPipe`, security descriptors, DACL
- `ImpersonateNamedPipeClient` — what it does to the thread token
- `OpenThreadToken` — capturing the impersonation token after impersonation
- Security Quality of Service — how the client controls the impersonation
  level it grants at connect time (`SECURITY_SQOS_PRESENT`,
  `SECURITY_IMPERSONATION` vs `SECURITY_IDENTIFICATION`)
- Why `SeImpersonatePrivilege` is required for this to work as a privesc

## The Potato Connection

The Potato family (RottenPotato → JuicyPotato → RoguePotato → GodPotato)
all fundamentally rely on this primitive — getting a SYSTEM-level process
(typically through DCOM/COM activation or the SYSTEM token coercion) to
connect to an attacker-controlled endpoint and impersonating it.
P06 is the raw primitive; C02 is the case study showing its evolution.

## Modes

| Mode | Description                                               | Severity |
|------|-----------------------------------------------------------|----------|
| 0    | SYSTEM service connects to attacker pipe (simulated)      | HIGH     |
| 1    | Client connects with SecurityImpersonation level          | HIGH     |
| 2    | Client connects with SecurityIdentification (not usable)  | LOW      |

## Lab Component
`P06_NamedPipeImpersonation.dll` loaded via `VulnLoader.exe 06 [mode]`

## Leads Into
P07 (RPC Process Creation — builds on impersonation concept),
P09 (Token Impersonation Level Confusion),
W01 (Token Impersonation to SYSTEM — weaponisation),
C02 (Potato Lineage — real-world application)
