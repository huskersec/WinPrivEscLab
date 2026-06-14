# H02 — NULL Page Mapping (Historical)

## Era
Windows XP through Windows 7 (32-bit). Mitigated in Windows 8+.

## Concept

On 32-bit Windows through Windows 7, a low-privileged usermode process could
call `NtAllocateVirtualMemory` to reserve and commit memory at virtual address
0 (the NULL page). When a kernel driver or win32k.sys dereferences a NULL
pointer while processing a usermode request, execution lands in attacker-
controlled memory rather than causing an access violation.

The usermode primitive is entirely unprivileged — any process can map the NULL
page. The exploitation depends on a corresponding kernel NULL pointer dereference
in a privileged component (typically win32k.sys GDI/User functions).

## Why It Matters Today

The mitigation history directly illustrates how Windows uses memory manager
policy as a security mechanism:

- **Windows 8+** — `NtAllocateVirtualMemory` refuses to allocate at address 0
  for non-kernel callers. This single policy change eliminated an entire
  exploitation technique class.
- **SMEP (Supervisor Mode Execution Prevention)** — even if a kernel NULL
  dereference occurs and user memory is mapped there, the CPU refuses to
  execute usermode pages in kernel context. Hardware enforcing what policy
  alone couldn't fully guarantee.
- **SMAP (Supervisor Mode Access Prevention)** — extends this to data access.

The lesson is architectural: the vulnerability is in the kernel driver, but
the *exploitability* depends entirely on a usermode capability (NULL page
mapping). Removing that capability breaks the exploit without fixing the
underlying kernel bug. This is the model for many modern Windows mitigations
— reduce the primitives available to an attacker rather than fixing every
possible bug.

## Connection to Modern Concepts

Win32k.sys isolation (Session 0 win32k vs user session win32k, introduced in
Server 2019) is a direct descendant of this design philosophy — reduce the
kernel attack surface accessible from unprivileged usermode contexts.

## Study Material
- Uninformed Journal Vol 7 — "Exploiting the otherwise non-exploitable"
- Tavis Ormandy's EPATHOBJ research (2013) — GDI object type confusion
- Windows 8 Security Whitepaper — NULL page allocation restriction

## No Lab Component
Not exploitable on any supported Windows version. Included as architectural
context only.

## Leads Into
P04 (Shared Memory Boundary), general kernel object model understanding
