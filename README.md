# Overview

Sample driver + user component to demonstrate writing into arbitrary process memory from Kernel via CR3 manipulation (opposed to the usual KeStackAttachProcess API).

Note: Only for fun and demonstration

# Fun

There's a few fun techniques in this that have been individually useful outside of this demo project. This includes:

- Halting all other cores/threads on the machine except my own executing code
- Providing windows and alternative x86-generic methods for certain things (e.g. IRQLs v CR8)
- Resolving offsets of unexported structures and union fields at runtime via runtime PDB parsing (instead of hardcoding offsets, etc)
- Modifying arbitrary user process memory from Kernel without KeStackAttachProcess (optionally checking VaSpaceDeleted via PDB-provided offsets)
- Surviving page-faults in >= DISPATCH without try/catch or letting the Kernel log the fault, achieved via IDT hijacking

This thing is also written in Rust.

For PDB parsing, I pulled in and modified pdblister https://github.com/microsoft/pdblister to support building as a lib.

# How to Use

- Navigate to read_write_driver
- run `cargo make` (sometimes it requires the first run to be done as administrator, you can safely ignore any "missing INF" related errors/warnings that pop up, build process also documented here: https://github.com/microsoft/windows-drivers-rs)
- Copy the driver (e.g for debug builds it'll be `read_write_driver\target\debug\read_write_driver.sys` to your target machine/VM
- Start the driver (e.g. in an administrator cmd prompt run `sc create readwrite binPath= C:\\code\\read_write_driver.sys type= kernel` followed by `sc start readwrite`. Replace the paths with your own)
- Navigate to `read_write_user` and build (e.g. `cargo build` or `cargo build --release`)
- Copy the binary (either `read_write_user\target\debug\read_write_user.exe` or `read_write_user\target\release\read_write_user.exe`) to your target machine/VM
- Find a PID and address in that PID you want to overwrite (e.g. launch notepad.exe, note its pid is 0x1234, attach a debugger and find some address in the target)
- If the address if valid + paged-in, it'll be overwritten with hardcoded sample bytes, if the address is invalid the driver will return an error to our userland process. No BSOD should occur regardless.
- Run the userland process, to run the example that'll leverage runtime PDB parsing add the `--use-symbols` flag, e.g. `read_write_user.exe --pid 0x1234 --address 0x100000 --use-symbols`. The address can be specified in hex (prefixed by `0x`) or in decimal without the prefix.
- If no error was displayed in the userland process, observe the modified bytes at your chosen address. 
