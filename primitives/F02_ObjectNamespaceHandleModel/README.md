# F02 — Windows Object Namespace and Handle Model

## Concept

Every kernel resource in Windows — files, sections, mutexes, events, processes,
threads — is represented as an Object Manager object. Access to these objects
from usermode is mediated through handles. Understanding the handle and namespace
model is prerequisite to every name-resolution primitive in this lab.

## Key Concepts

### The Object Manager Namespace
A hierarchical directory tree rooted at `\`. Key nodes:
- `\BaseNamedObjects`        — global named objects (legacy, session 0)
- `\Sessions\N\BaseNamedObjects` — per-session named objects (N = session ID)
- `\KnownDLLs`              — trusted DLL mappings
- `\Device`                 — device objects
- `\REGISTRY`               — registry namespace root

### Why Session Namespace Matters
Low-privileged users can create objects in their own session's
`\Sessions\N\BaseNamedObjects`. This is by design — applications need to
create named synchronisation objects. The security assumption is that objects
in your session namespace are yours. The vulnerability class arises when a
SYSTEM process also creates objects in the same namespace.

### Handles
A handle is a process-local reference to a kernel object. Key properties:
- Handle values are per-process (same value in two processes = different objects)
- Access rights are fixed at open time
- Handles can be inherited, duplicated, or leaked
- The kernel object persists as long as at least one handle references it

### Object Attributes and Name Resolution
`NtCreateSection` and friends take an `OBJECT_ATTRIBUTES` struct containing:
- `ObjectName`  — UNICODE_STRING path to the object
- `RootDirectory` — optional handle to a directory object (relative paths)
- `Attributes` — flags including `OBJ_OPENIF`, `OBJ_CASE_INSENSITIVE`

Name resolution traverses the directory tree following symbolic links
transparently — this is the property exploited in P01 and P02.

## Demonstration

`NamespaceExplorer.exe` — enumerates `\Sessions\N\BaseNamedObjects` using
`NtOpenDirectoryObject` and `NtQueryDirectoryObject`, printing all objects
with their type and name. Run before and after VulnLoader to observe the
section appearing and disappearing.

## Prerequisites
F01 (TOCTOU concept)

## Leads Into
P01 (Object Manager Symlink), P02 (Registry Symlink), P04 (Shared Memory),
P05 (Handle Inheritance)
