# P02 — Registry Symbolic Link Abuse

## Prerequisites
F01 (TOCTOU), F02 (Object Namespace), P01 (Object Manager Symlink)

## Vulnerability Class

The Windows registry is a namespace with its own symbolic link mechanism —
`REG_OPTION_CREATE_LINK` keys with a `SymbolicLinkValue` entry. Like Object
Manager symlinks, registry symlinks are followed transparently during name
resolution. A low-privileged user who can delete and recreate a registry key
can replace it with a symlink redirecting reads and writes to an arbitrary
target key.

The secondary primitive here is DACL manipulation via `TreeSetNamedSecurityInfo`
— policy keys are sometimes protected with restrictive DACLs that must be
reset before the symlink can be planted.

## Pattern vs P01

P01: Object Manager namespace, `NtCreateSymbolicLinkObject`
P02: Registry namespace, `RegCreateKeyEx` with `REG_OPTION_CREATE_LINK`

Same TOCTOU concept, different namespace. After P01 this should feel familiar.

## Real-World Example

GreenPlasma `SetPolicyVal()`:
- Resets DACL on `HKCU\Software\Policies\Microsoft\CloudFiles`
- Deletes `BlockedApps` subkey
- Recreates it as a registry symlink pointing to
  `\REGISTRY\USER\<SID>\Software\Microsoft\Windows\CurrentVersion\Policies\System`
- Any privileged reader of `BlockedApps` now reads/writes `Policies\System`

## Modes

| Mode | Description                                          | Severity |
|------|------------------------------------------------------|----------|
| 0    | BLIND — no existence check before key create         | HIGH     |
| 1    | CHECKFIRST — RegOpenKey check then create (TOCTOU)   | MEDIUM   |
| 2    | Volatile link — REG_OPTION_VOLATILE (in-memory only) | MEDIUM   |

## Lab Component
`P02_RegSymlinkHijack.dll` loaded via `VulnLoader.exe 02 [mode]`

## Leads Into
P03 (NTFS Junction — completes the name resolution trilogy), C03 (GreenPlasma)
