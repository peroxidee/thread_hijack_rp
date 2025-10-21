EXTERN wrdNtSuspendThread:DWORD   
EXTERN wrdNtAllocateVirtualMemory:DWORD   
EXTERN wrdNtSuspendThread:DWORD   
EXTERN wrdNtWriteVirtualMemory:DWORD   
EXTERN wrdNtGetContextThread:DWORD   
EXTERN wrdNtSetContextThread:DWORD   
EXTERN wrdNtResumeThread:DWORD   
EXTERN wrdNtOpenProcess:DWORD   
EXTERN wrdNtOpenThread:DWORD

EXTERN sysNtSuspendThread:QWORD   
EXTERN sysNtAllocateVirtualMemory:QWORD   
EXTERN sysNtSuspendThread:QWORD   
EXTERN sysNtWriteVirtualMemory:QWORD   
EXTERN sysNtGetContextThread:QWORD   
EXTERN sysNtSetContextThread:QWORD   
EXTERN sysNtResumeThread:QWORD   
EXTERN sysNtOpenProcess:QWORD   
EXTERN sysNtOpenThread:QWORD

.CODE;


;

NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wrdNtWriteVirtualMemory
    jmp QWORD PTR [sysNtWriteVirtualMemory]
    ret
NtWriteVirtualMemory ENDP


;
NtOpenProcess PROC
    mov r10, rcx
    mov eax, wrdNtOpenProcess
    jmp QWORD PTR [sysNtOpenProcess]
    ret
NtOpenProcess ENDP
;
NtOpenThread PROC
    mov r10, rcx
    mov eax, wrdNtOpenThread
    jmp QWORD PTR [sysNtOpenThread]
    ret
NtOpenThread ENDP
;

NtGetContextThread PROC
    mov r10, rcx
    mov eax, wrdNtGetContextThread
    jmp QWORD PTR [sysNtGetContextThread]
    ret
NtGetContextThread ENDP
;
NtSetContextThread PROC
    mov r10, rcx
    mov eax, wrdNtSetContextThread
    jmp QWORD PTR [sysNtSetContextThread]
    ret
NtSetContextThread ENDP
;
NtResumeThread PROC
    mov r10, rcx
    mov eax, wrdNtResumeThread
    jmp QWORD PTR [sysNtResumeThread]
    ret
NtResumeThread ENDP
;
NtSuspendThread PROC
    mov r10, rcx
    mov eax, wrdNtSuspendThread
    jmp QWORD PTR [sysNtSuspendThread]
    ret
NtSuspendThread ENDP
;
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wrdNtAllocateVirtualMemory
    jmp QWORD PTR [sysNtAllocateVirtualMemory]
    ret
NtAllocateVirtualMemory ENDP

END;