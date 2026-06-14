# P07 — RPC Process Creation Under Impersonation

## Prerequisites
F03 (Token and Integrity Model), F04 (IPC Mechanisms), P06 (Named Pipe
Impersonation)

## Vulnerability Class

Documented by James Forshaw and demonstrated in practice by FortiGuard Labs
(CVE-2019-1287). An RPC server calls `RpcImpersonateClient` to impersonate
the caller, then spawns a child process via `CreateProcess` rather than
`CreateProcessAsUser` with an explicit token.

The critical behaviour: `CreateProcess` inherits the primary token of the
calling *process*, not the thread's current impersonation token. The
impersonation state affects what resources the *thread* can access during
the call, but the spawned process always gets the server's process token.

If the server is SYSTEM and the client is an unprivileged attacker, the
attacker can trigger a `CreateProcess` call and the resulting process runs
as SYSTEM — regardless of the impersonation state at the time of the call.

Combined with P03 (NTFS junction to redirect the executable path), this
becomes a reliable SYSTEM code execution primitive.

## The Correct vs Incorrect Pattern

Incorrect (vulnerable):
```c
RpcImpersonateClient(hBinding);
CreateProcess(L"C:\\path\\tool.exe", ...);  // inherits server (SYSTEM) token
RpcRevertToSelf();
```

Correct (safe):
```c
RpcImpersonateClient(hBinding);
OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken);
DuplicateTokenEx(hToken, ..., TokenPrimary, &hPrimary);
CreateProcessAsUser(hPrimary, L"C:\\path\\tool.exe", ...);
RpcRevertToSelf();
```

## What This Teaches

- `RpcImpersonateClient` / `RpcRevertToSelf` semantics
- Thread token vs process token in `CreateProcess` context
- Why `CreateProcessAsUser` with an explicit token is required under
  impersonation
- RPC interface discovery and client implementation
- How to combine with P03 to redirect the executable path

## Real-World Examples

- CVE-2019-1287 — NcaSvc.dll `Rpc_NcaExecuteAndCaptureLogs` spawning
  PowerShell under impersonation
- Multiple Windows diagnostic and VPN services with the same pattern
- PrintNightmare (C01) — spooler's AddPrinterDriverEx triggering a
  privileged LoadLibrary under impersonation

## Modes

| Mode | Description                                               | Severity |
|------|-----------------------------------------------------------|----------|
| 0    | CreateProcess under impersonation — executable path fixed | HIGH     |
| 1    | CreateProcess under impersonation — path user-influenced  | CRITICAL |
| 2    | CreateProcessAsUser (correct implementation, for contrast) | NONE    |

## Lab Component
`P07_RPCProcessCreation.dll` loaded via `VulnLoader.exe 07 [mode]`

## Leads Into
C01 (PrintNightmare — P03 + P07), C02 (Potato Lineage),
W01 (Token Impersonation to SYSTEM)
