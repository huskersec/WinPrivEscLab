# P03 — NTFS Junction / Hardlink Attack Against Privileged File Operations

## Prerequisites
F01 (TOCTOU), F02 (Object Namespace), P01, P02

## Vulnerability Class

The NTFS filesystem supports two redirection mechanisms exploitable against
privileged file operations:

**Junctions (Directory Symlinks)** — a reparse point that redirects directory
traversal to an arbitrary target path. Any user can create a junction to any
directory. When a privileged process creates or writes a file under a path
that traverses an attacker-controlled junction, the file lands at the
attacker's target.

**Hardlinks** — multiple directory entries pointing to the same inode. A
standard user can create a hardlink to any file they have read access to,
even if they cannot write it. When a privileged process writes to the
hardlink's path, it writes to the original file.

Together these complete the name resolution trust trilogy:
- Object Manager namespace — P01 (symbolic links)
- Registry namespace       — P02 (registry symlinks)
- NTFS filesystem          — P03 (junctions and hardlinks)

## The Privileged File Operation Pattern

The vulnerable pattern is a SYSTEM process that:
1. Creates or writes a file to a path the attacker influences, OR
2. Deletes a file and recreates it (delete-create race), OR
3. Uses `MoveFile` or similar across a junction boundary

Common real-world triggers: installers, Windows Update, crash handlers,
diagnostic tools, print spooler (C01).

## Mitigations Worth Understanding

- `FILE_FLAG_OPEN_REPARSE_POINT` — opens the reparse point itself, not the
  target. Used to prevent following junctions.
- `FILE_FLAG_NO_FOLLOW` — Win10 1703+. Causes open to fail if any component
  of the path is a reparse point.
- Oplock (opportunistic lock) tricks — used by researchers to widen the race
  window artificially, pausing a SYSTEM file operation mid-path-traversal.

## Modes

| Mode | Description                                           | Severity |
|------|-------------------------------------------------------|----------|
| 0    | Junction — privileged write through user junction     | HIGH     |
| 1    | Hardlink — privileged overwrite via hardlink          | HIGH     |
| 2    | Oplock-assisted — widened race window via oplock      | HIGH     |

## Lab Component
`P03_NTFSJunctionHardlink.dll` loaded via `VulnLoader.exe 03 [mode]`

## Leads Into
P04 (Shared Memory), C01 (PrintNightmare — P03 + P07 combined),
C03 (GreenPlasma — filesystem redirection component)
