# P09 — Token Impersonation Level Confusion

## Prerequisites
F03 (Token and Integrity Model), P06 (Named Pipe Impersonation)

## Vulnerability Class

A privileged service grants or accepts an impersonation token at a higher
level than intended, or fails to validate the impersonation level of a
token before using it for sensitive operations. The result is an attacker
obtaining a usable impersonation token from a context where only an
identification-level token should have been possible.

The four impersonation levels determine what a server can do with a client
token after impersonation:

| Level              | Server can identify? | Server can act locally? | Server can act remotely? |
|--------------------|---------------------|-------------------------|--------------------------|
| Anonymous          | No                  | No                      | No                       |
| Identification     | Yes                 | No                      | No                       |
| Impersonation      | Yes                 | Yes                     | No                       |
| Delegation         | Yes                 | Yes                     | Yes                      |

The vulnerability is a service expecting Identification-level tokens (for
audit/logging) but receiving Impersonation-level tokens it then uses in
sensitive operations without checking the level.

## What This Teaches

- `GetTokenInformation(TokenImpersonationLevel)` — how to check the level
  of a token before using it
- How clients control the level they grant —
  `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` vs
  `SECURITY_IDENTIFICATION` in `CreateFile` / connection calls
- `DuplicateToken` vs `DuplicateTokenEx` — how to create tokens at a
  specific impersonation level
- Why RPC and ALPC servers should always check the impersonation level
  of tokens they receive before acting on them
- The historical pattern of services receiving higher-level tokens than
  designed for due to client-controlled QoS parameters

## Modes

| Mode | Description                                                 | Severity |
|------|-------------------------------------------------------------|----------|
| 0    | Server accepts any level, uses token without checking       | HIGH     |
| 1    | Server checks level but comparison is inverted (logic bug)  | HIGH     |
| 2    | Server checks correctly — for contrast                      | NONE     |

## Lab Component
`P09_TokenImpersonationLevel.dll` loaded via `VulnLoader.exe 09 [mode]`

## Leads Into
P10 (MIC/COM — integrity levels interact with impersonation levels),
W01 (Token Impersonation to SYSTEM — impersonation level determines
whether the token is usable for process creation)
