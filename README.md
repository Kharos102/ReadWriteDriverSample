# Overview

Sample driver + user component to demonstrate writing into arbitrary process memory from Kernel via CR3 manipulation (opposed to the usual KeStackAttachProcess API).

Note: Only for fun and demonstration

# Fun

There's a few fun techniques in this that have been individually useful outside of this demo project. This includes:

- Halting all other cores/threads on the machine except my own executing code
- Resolving offsets of unexported structures and union fields at runtime via runtime PDB parsing (instead of hardcoding offsets, etc)
- Modifying arbitrary user process memory from Kernel without KeStackAttachProcess (optionally checking VaSpaceDeleted via PDB-provided offsets)
- Surviving page-faults in >= DISPATCH without try/catch or letting the Kernel log the fault, achieved via IDT hijacking

This thing is also written in Rust.
