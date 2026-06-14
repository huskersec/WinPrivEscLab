# W02 — Shared Memory Content Injection

## Prerequisites
F02 (Object Namespace and Handle Model), P01 (Object Manager Symlink),
P04 (Shared Memory Boundary Violation)

## Weaponization Concept

Given a writable handle to a SYSTEM-owned section object (acquired via P01
or P04), this module demonstrates how write access to shared memory translates
into behavioral influence over the privileged process that owns it.

## The Trust Problem

Shared memory IPC requires both parties to trust the data they read. A SYSTEM
process reading from a shared section should treat that data with the same
suspicion as network input — the sender cannot be verified. In practice,
many IPC implementations trust shared memory implicitly because the section
was "created by us" — without accounting for the possibility that an attacker
holds a handle to the same section via a symlink hijack.

## Attack Patterns

**Canary/Struct Overwrite** — simplest form. Overwrite a known struct
(like `LAB_CANARY`) to prove write access and observe the privileged process
reacting to corrupted state.

**Command Buffer Injection** — if the shared section contains a command
or request buffer that the SYSTEM process reads and executes, attacker
writes a crafted command. Common in IPC protocols where the section holds
a "request queue" or "pending operations" list.

**Function Pointer Overwrite** — if the shared section contains a vtable
pointer, callback address, or function pointer that the SYSTEM process
dereferences, overwriting it redirects execution into attacker-controlled
code. Requires the section to be mapped executable (Mode 2 of P04).

## What This Teaches

- Mapping a view of an existing section via `NtMapViewOfSection`
- Reading and writing across a privilege boundary through shared pages
- Why input validation in shared memory consumers is non-negotiable
- The difference between proving write access (canary overwrite) and
  achieving code execution (pointer overwrite)
- Relationship to modern exploit mitigations — CFG, ACG, and how they
  constrain what an attacker can do with a write primitive

## Lab Exercise

Starting from the section handle acquired in P01/P04:
1. Map the section view in the attacker process
2. Read the current LAB_CANARY struct — confirm SYSTEM ownership
3. Overwrite Magic with LAB_CANARY_MAGIC_BAD — observe VulnLoader react
4. Write a crafted command buffer entry
5. Observe the privileged process process the injected command

## Leads Into
W03 (Token Privilege Manipulation), W04 (Cross-Process Memory Access)
