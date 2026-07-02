# F01 — TOCTOU (Time of Check to Time of Use)

## Concept

TOCTOU is a class of race condition vulnerability where a program checks a
condition and then acts on it, but the state of the world can change between
the check and the act. If an attacker can influence that state change, the
action executes under false assumptions.

The abstract pattern:

```
1. CHECK  — verify some condition (does this file exist? is this object safe?)
2. [race window]
3. ACT    — perform an operation assuming the check result is still valid
```

If the attacker can modify the checked resource during the race window, the
ACT executes on attacker-controlled state.

## Why It Matters for Windows Privesc

Every name resolution primitive in Windows is susceptible to TOCTOU:
- Object Manager namespace  (P01)
- Registry namespace        (P02)
- NTFS filesystem           (P03)

In each case a privileged process checks whether a named resource exists,
then creates or opens it — and an attacker can insert a malicious object
between those two operations.

## Demonstration

`ToctouDemo.exe` — a minimal self-contained race condition with no Windows
privesc involved. A "checker" thread verifies a temp file doesn't exist then
creates it. A "racer" thread creates the file in the window between check and
create. Observable output shows which thread won the race.

Concepts demonstrated:
- Race window width vs. thread scheduling
- Why Sleep() between check and act widens the window (as seen in VulnLoader Mode 1)
- Why atomic operations (create-exclusive) close the window
- How narrowing the window reduces but does not eliminate exploitability

## Prerequisites
None — this is the starting point.

## Leads Into
F02 (Object Namespace), P01 (Object Manager Symlink), P02 (Registry Symlink),
P03 (NTFS Junction)
