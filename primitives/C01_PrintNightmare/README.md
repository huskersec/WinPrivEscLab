# C01 — PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

## Prerequisites
P03 (NTFS Junction / Hardlink), P07 (RPC Process Creation Under Impersonation)

## Case Study Overview

PrintNightmare is the synthesis of two primitives studied in this lab:
- P03: filesystem redirection via a user-controlled path
- P07: a privileged RPC server spawning a process (LoadLibrary) under
  impersonation without using an explicit token

The Windows Print Spooler service (`spoolsv.exe`) runs as SYSTEM and exposes
an RPC interface. `AddPrinterDriverEx` is an RPC method that installs a
printer driver — it accepts a UNC path to a DLL and calls `LoadLibrary` on
it as SYSTEM. A low-privileged user can call this method to load an arbitrary
DLL as SYSTEM.

## The Chain

```
Unprivileged user
  -> Calls AddPrinterDriverEx RPC with a UNC path to attacker DLL
  -> Spooler (SYSTEM) calls LoadLibrary on the attacker-supplied path
  -> DLL loads in SYSTEM context
  -> DllMain executes arbitrary code as SYSTEM
```

## Why P03 Is Involved

The DLL path can be a UNC path (`\\attacker\share\evil.dll`) or a local
path traversing an attacker-controlled junction. The spooler's path handling
before the LoadLibrary call was vulnerable to junction redirection — allowing
a local attacker without network access to redirect the load to an arbitrary
DLL.

## Why P07 Is Involved

The spooler calls `LoadLibrary` (which internally uses `CreateProcess`-like
semantics for DLL loading) while operating in an impersonated client context.
The DLL load happens under the server's SYSTEM token, not the impersonated
client's token — precisely the P07 pattern.

## What This Teaches

- How two individually-understood primitives combine into a complete exploit
- The spooler's RPC interface — `MS-RPRN` protocol
- Why privileged services that accept file paths from unprivileged callers
  are inherently dangerous
- Microsoft's patch history — the vulnerability was partially patched,
  bypassed, re-patched, and had variants found for months
- The difference between CVE-2021-1675 (local LPE) and CVE-2021-34527
  (remote RCE via the same code path)

## Study Approach

1. Read the spooler's `AddPrinterDriverEx` implementation conceptually
2. Map each step to either P03 or P07 primitives already understood
3. Understand why the fix (checking caller privilege before LoadLibrary)
   was the correct mitigation
4. Research the bypass variants to understand why partial patches fail

## No Full PoC in This Lab

PrintNightmare is fully patched. This case study is analytical only —
connecting the dots between the primitives you have built rather than
providing new exploit code.

## Reference Material
- Original Sangfor disclosure (June 2021)
- cube0x0 and calebstewart public PoC analyses
- Microsoft MSRC advisory CVE-2021-34527
- James Forshaw's analysis of the patch and bypass
