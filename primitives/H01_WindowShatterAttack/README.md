# H01 — Window Message Shatter Attack (Historical)

## Era
Windows XP / pre-Vista. No longer exploitable on modern Windows.

## Concept

Before Vista, all processes running in the same window station (including
services and interactive user applications) shared the same message queue
and could send arbitrary window messages to each other regardless of privilege.
A low-privileged process could craft malicious window messages targeting
windows owned by a SYSTEM-level process, causing code execution in the
privileged context.

The attack name "shatter" refers to shattering the security boundary between
privilege levels by abusing the window message system.

## Why It Matters Today

Microsoft's response to shatter attacks directly shaped the modern Windows
desktop security architecture:

- **UIPI (User Interface Privilege Isolation)** — introduced in Vista.
  Lower-integrity processes cannot send most window messages to
  higher-integrity windows. `PostMessage`/`SendMessage` are blocked across
  integrity levels except for a small whitelist.

- **Window Station and Desktop isolation** — services now run in Session 0,
  completely isolated from interactive user sessions. Before Vista, services
  ran in Session 1 alongside the user.

- **The Winlogon desktop** — the secure desktop used for UAC prompts and the
  lock screen runs in a separate desktop object (`Winlogon`) isolated from the
  user's default desktop (`Default`). This isolation is why ctfmon's
  `FMPWinlogon` objects are specifically tied to the Winlogon desktop context —
  the desktop boundary is a security decision with direct lineage to shatter.

## Connection to Modern Vulnerabilities

GreenPlasma (C03) explicitly exploits the boundary between the Default and
Winlogon desktops — the `OpenInputDesktop` loop detects the desktop transition.
Understanding *why* that boundary exists and what it was designed to prevent
makes GreenPlasma's technique much clearer.

## Study Material
- Phrack 62 — "Exploiting the Windows Kernel" (shatter attack original paper)
- MS04-011 and related advisories
- Vista UIPI design documentation

## No Lab Component
This primitive is not exploitable on any supported Windows version and has
no associated VulnLoader primitive. It is included as architectural context
only.

## Leads Into
P01 (Object Manager Symlink — Winlogon desktop context),
C03 (GreenPlasma — desktop transition synchronisation)
