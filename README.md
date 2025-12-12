# Thread Execution Hijacking PoCs (T1055.003)

A series of four different proof-of-concepts built for an INSURE research project based around finding the invariant behavior of T1055.003. The four techniques it touches on are:

- Winapi: Basic winapi usage, no evasion techniques
- NtAPI: Native Api usage of the thread, nt function calls resolved via walking the PEB and the EAT.
- Direct Syscalls: NtAPI usage, but incorporates the Direct Syscalls technique.
- Indirect Syscalls: NtAPI usage, but incorporates the Indirect Syscalls technique.

All four programs can be run via:
```
./THREAD_EXE_HIJACKING [pid] [tid]
```
