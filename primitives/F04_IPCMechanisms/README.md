# F04 — Windows IPC Mechanisms Overview

## Concept

Windows provides several inter-process communication mechanisms. Three are
directly relevant to privilege escalation: Named Pipes, RPC, and ALPC. Each
builds on the previous — RPC typically runs over named pipes or ALPC, and
ALPC is the kernel substrate underneath both. Understanding the trust model
of each is prerequisite to P06, P07, and P08.

## Mechanisms

### Named Pipes
A named pipe is a one-way or duplex communication channel with a name in the
filesystem namespace (`\\.\pipe\name`). Key security properties:
- The server creates the pipe and controls its DACL
- The client connects and the server can call `ImpersonateNamedPipeClient`
  to assume the client's security context
- The impersonation level the client grants is controlled at connect time
  via `CreateFile` security QoS flags
- Privileged processes that connect to attacker-controlled pipes are the
  foundation of the Potato family and P06

### RPC (Remote Procedure Call)
RPC is a protocol that allows calling functions in another process (or machine)
as if they were local. On Windows:
- RPC servers expose interfaces identified by a UUID
- Transport can be named pipes (`ncacn_np`), TCP (`ncacn_ip_tcp`), or ALPC
- The server can call `RpcImpersonateClient` to impersonate the caller
- The vulnerability in P07 arises when `CreateProcess` is called while
  impersonating — the new process inherits the server token, not the client's

### ALPC (Advanced Local Procedure Call)
ALPC is the kernel-level IPC mechanism that underlies most Windows service
communication. Named pipes and RPC over local transports use ALPC internally:
- ALPC ports are kernel objects (`\...\RPC Control\...`)
- Messages are passed synchronously or asynchronously
- Connection security is enforced via port DACLs and security descriptors
- Unlike named pipes, ALPC is not directly accessible via Win32 — requires
  NT native API (`NtCreateAlpcPort`, `NtAlpcConnectPort`)
- P08 works directly at this layer

## Trust Model Comparison

| Mechanism   | Server creates | Client connects | Impersonation via            |
|-------------|---------------|-----------------|------------------------------|
| Named Pipe  | CreateNamedPipe | CreateFile     | ImpersonateNamedPipeClient   |
| RPC         | RpcServerUseProtseq | RPC client  | RpcImpersonateClient         |
| ALPC        | NtCreateAlpcPort | NtAlpcConnectPort | NtAlpcImpersonateClientOfPort |

In all three cases the server can impersonate the client. The vulnerability
arises when a privileged server impersonates an attacker-controlled client.

## Prerequisites
F03 (Token and Integrity Model)

## Leads Into
P06 (Named Pipe Impersonation), P07 (RPC Process Creation), P08 (ALPC Abuse)
