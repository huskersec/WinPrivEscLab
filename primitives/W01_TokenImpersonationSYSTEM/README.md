# W01 — Token Impersonation to SYSTEM Process Spawn

## Prerequisites
F03 (Token and Integrity Model), P06 (Named Pipe Impersonation),
P07 (RPC Process Creation), P09 (Token Impersonation Level Confusion)

## Weaponization Concept

Given an impersonation token acquired from any of P06, P07, or P09 — this
module demonstrates how to convert it into a SYSTEM process. This is the
"last mile" of most practical LPE chains.

## The Chain

```
Impersonation token (from P06/P07/P09)
    -> DuplicateTokenEx (Impersonation -> Primary)
    -> CreateProcessWithTokenW or CreateProcessAsUser
    -> SYSTEM shell / arbitrary process
```

## Key API Concepts

**DuplicateTokenEx** — converts an impersonation token to a primary token,
which is required for `CreateProcessWithTokenW`. Key parameters:
- `ImpersonationLevel` must be `SecurityImpersonation` or higher (P09)
- `TokenType` set to `TokenPrimary` for process creation

**CreateProcessWithTokenW** vs **CreateProcessAsUser**
- `CreateProcessWithTokenW` — requires `SeImpersonatePrivilege`, simpler
- `CreateProcessAsUser` — requires `SeAssignPrimaryTokenPrivilege`,
  more control over the environment

**CreateEnvironmentBlock** — builds the correct environment for the
target user's token. Often missed, causes processes to spawn with a
broken environment.

**lpDesktop** — must be set to `winsta0\default` to spawn an interactive
process visible on the user's desktop.

## What This Teaches

- The complete token-to-process chain
- Why impersonation level matters at the duplication step
- Privilege requirements for each process creation API
- Desktop and window station assignment for interactive processes
- Why a SYSTEM token without `SeImpersonatePrivilege` in the attacker's
  current process cannot be used for this chain

## Lab Exercise

Starting from a token handle obtained via P06's simulated pipe server:
1. Check impersonation level via `GetTokenInformation`
2. Duplicate to primary token
3. Spawn `cmd.exe` as SYSTEM with an interactive desktop
4. Verify via `whoami` in the spawned shell

## Leads Into
W02 (Shared Memory Injection), W03 (Token Privilege Manipulation)
