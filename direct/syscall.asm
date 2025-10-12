EXTERN wrdNtSuspendThread:DWORD   
EXTERN wrdNtAllocateVirtualMemory:DWORD   
EXTERN wrdNtSuspendThread:DWORD   
EXTERN wrdNtWriteVirtualMemory:DWORD   
EXTERN wrdNtGetContextThread:DWORD   
EXTERN wrdNtSetContextThread:DWORD   
EXTERN wrdNtResumeThread:DWORD   
EXTERN wrdNtOpenProcess:DWORD   
EXTERN wrdNtOpenThread:DWORD



.CODE;




NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wrdNtWriteVirtualMemory
    syscall
    ret
NtWriteVirtualMemory ENDP

NtOpenProcess PROC
    mov r10, rcx
    mov eax, wrdNtOpenProcess
    syscall
    ret
NtOpenProcess ENDP

NtOpenThread PROC
    mov r10, rcx
    mov eax, wrdNtOpenThread
    syscall
    ret
NtOpenThread ENDP


NtGetContextThread PROC
    mov r10, rcx
    mov eax, wrdNtGetContextThread
    syscall
    ret
NtGetContextThread ENDP

NtSetContextThread PROC
    mov r10, rcx
    mov eax, wrdNtSetContextThread
    syscall
    ret
NtSetContextThread ENDP

NtResumeThread PROC
    mov r10, rcx
    mov eax, wrdNtResumeThread
    syscall
    ret
NtResumeThread ENDP

NtSuspendThread PROC
    mov r10, rcx
    mov eax, wrdNtSuspendThread
    syscall
    ret
NtSuspendThread ENDP

NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wrdNtAllocateVirtualMemory
    syscall
    ret
NtAllocateVirtualMemory ENDP