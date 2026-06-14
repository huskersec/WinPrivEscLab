# P08 — ALPC Interface Abuse

## Prerequisites
F03 (Token and Integrity Model), F04 (IPC Mechanisms), P06 (Named Pipe),
P07 (RPC Process Creation)

## Vulnerability Class

ALPC (Advanced Local Procedure Call) is the kernel-level IPC substrate that
underlies named pipes, RPC local transports, and most internal Windows service
communication. Unlike named pipes and RPC, ALPC is not directly exposed via
Win32 — it requires NT native API. Most Windows services communicate via ALPC
ports without developers (or attackers) realising it.

The vulnerability class mirrors P06 and P07 but at a lower level: a privileged
ALPC server accepts connections from unprivileged clients and either impersonates
them insecurely or processes attacker-controlled message content without
validation.

## What This Teaches

- ALPC port objects in the object namespace (`\RPC Control\*`)
- `NtCreateAlpcPort` / `NtAlpcConnectPort` — server and client setup
- `NtAlpcSendWaitReceivePort` — message passing
- `NtAlpcImpersonateClientOfPort` — impersonation at the ALPC level
- ALPC message structure — `PORT_MESSAGE` header, data sections
- How to enumerate ALPC ports on a running system using
  `NtQuerySystemInformation` and WinObj
- Why Task Scheduler, LSA, and other core services expose ALPC interfaces
  that have historically been vulnerable (CVE-2018-0952 and the task
  scheduler hardlink family)

## ALPC as a Discovery Surface

Understanding ALPC opens a significant research surface. Every Windows service
with an ALPC port is potentially a target for:
- Message structure fuzzing
- Impersonation capture
- Port connection security descriptor weaknesses

Tools: `AlpcMon`, WinObj (`\RPC Control`), NtObjectManager PowerShell module
(James Forshaw).

## Modes

| Mode | Description                                               | Severity |
|------|-----------------------------------------------------------|----------|
| 0    | ALPC server impersonates client insecurely                | HIGH     |
| 1    | ALPC server processes message without validation          | MEDIUM   |
| 2    | ALPC port with weak security descriptor                   | HIGH     |

## Lab Component
`P08_ALPCAbuse.dll` loaded via `VulnLoader.exe 08 [mode]`

## Leads Into
C02 (Potato Lineage — ALPC/RPC substrate),
C03 (GreenPlasma — ALPC underlies CTF communication)
