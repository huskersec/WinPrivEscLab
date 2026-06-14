# C02 — The Potato Family Lineage

## Prerequisites
F03 (Token and Integrity Model), F04 (IPC Mechanisms),
P06 (Named Pipe Impersonation), P07 (RPC Process Creation),
P09 (Token Impersonation Level Confusion), P10 (MIC/COM Auto-Elevation)

## Case Study Overview

The Potato family represents the single best documented case study in how a
vulnerability class evolves as Microsoft applies successive mitigations. Each
generation was forced into a new technique by a specific defensive change.
Understanding the full lineage teaches both the underlying primitives and how
to reason about mitigation effectiveness.

All Potato variants share one fundamental goal: coerce a SYSTEM-level process
into authenticating to an attacker-controlled endpoint, then capture and use
the resulting token. The primitive is P06 at its core — named pipe or socket
impersonation. The variation across generations is in *how* SYSTEM is coerced.

---

## RottenPotato (2016)

**Primitive:** DCOM activation + NTLM reflection over local loopback

**Technique:**
A process holding `SeImpersonatePrivilege` activates a DCOM object
(`BITS`, `wuauserv`, etc.) which causes the SYSTEM DCOM server to authenticate
to the attacker via NTLM over a local socket. The attacker reflects this
authentication to a local named pipe, capturing a SYSTEM impersonation token
via `ImpersonateNamedPipeClient`.

**Mitigation applied:**
MS16-075 / KB3164038 — blocked NTLM reflection to the same host. A machine
account can no longer authenticate to itself via NTLM relay.

**What it teaches:** DCOM activation mechanics, NTLM authentication flow,
local NTLM reflection, why machine account authentication to localhost was
a security boundary.

---

## JuicyPotato (2018)

**Primitive:** COM server abuse + NTLM authentication coercion

**Technique:**
MS16-075 blocked NTLM reflection but not COM activation abuse more broadly.
JuicyPotato allowed specifying arbitrary CLSID values and DCOM server ports,
enabling selection of COM objects that would cause SYSTEM authentication
without using the blocked reflection path. Worked on Windows 7 through
Server 2016.

**Mitigation applied:**
Windows 10 1809 / Server 2019 — restricted which COM objects service accounts
could activate, and tightened the DCOM authentication coercion paths.

**What it teaches:** COM CLSID enumeration, DCOM security configuration,
why the 1809 changes specifically targeted this class.

---

## RoguePotato (2020)

**Primitive:** OXID resolver manipulation + named pipe impersonation

**Technique:**
After 1809 tightened DCOM activation, RoguePotato manipulated the OXID
(Object Exporter ID) resolver — the mechanism Windows uses to locate DCOM
objects across machines. By redirecting OXID resolution to an attacker-
controlled endpoint, SYSTEM authentication could be coerced without direct
DCOM activation abuse. Restored reliable exploitation on Server 2019.

**Mitigation applied:**
No single patch — Microsoft hardened OXID resolver behaviour incrementally.

**What it teaches:** DCOM marshalling, OXID resolution, distributed COM
security model, why RPC endpoint registration is a security surface.

---

## GodPotato (2023)

**Primitive:** IRemUnknown2 interface + ALPC

**Technique:**
Leverages the `IRemUnknown2` COM interface over ALPC to coerce SYSTEM
authentication without relying on any of the previously patched DCOM
activation or NTLM reflection paths. Works on Windows 10/11 and Server
2022 as of release.

**What it teaches:** The ALPC substrate underneath COM (connecting directly
to P08), IRemUnknown2 interface semantics, why the COM/ALPC boundary
remains a persistent attack surface.

---

## The Lineage as a Lesson in Mitigation Design

Each Microsoft fix closed a specific path while leaving the fundamental
primitive (coerce SYSTEM to authenticate to attacker endpoint, capture
token) intact. This is the central lesson:

**Patching the path is not the same as patching the primitive.**

As long as any mechanism exists for coercing a SYSTEM-level process to
initiate an authenticated connection to a user-controlled endpoint, and as
long as `SeImpersonatePrivilege` allows capturing and using that token,
some variant of this attack is possible.

The correct mitigation would be removing `SeImpersonatePrivilege` from
service accounts that do not need it — but this breaks legitimate
functionality for many services.

## Study Approach

Work through each generation:
1. Identify which primitive from the lab it uses (P06, P07, P08, P09)
2. Identify what specific Windows behaviour it relies on
3. Identify what the Microsoft fix changed
4. Identify why the next generation was still possible despite the fix

## Reference Material
- foxglovesecurity "Rotten Potato" blog (2016)
- ohpe/decoder JuicyPotato GitHub and documentation
- splinter_code/decoder RoguePotato paper
- BeichenDream GodPotato analysis
- James Forshaw — "Windows Privilege Escalation via the DCOM and NTLM"
