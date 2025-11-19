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


NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wrdNtWriteVirtualMemory
    jmp QWORD PTR [sysNtWriteVirtualMemory]
NtWriteVirtualMemory ENDP


;
NtOpenProcess PROC
    mov r10, rcx
    mov eax, wrdNtOpenProcess
    jmp QWORD PTR [sysNtOpenProcess]
NtOpenProcess ENDP

;
NtOpenThread PROC
    mov r10, rcx
    mov eax, wrdNtOpenThread
    jmp QWORD PTR [sysNtOpenThread]
NtOpenThread ENDP
;

NtGetContextThread PROC
    mov r10, rcx
    mov eax, wrdNtGetContextThread
    jmp QWORD PTR [sysNtGetContextThread]
NtGetContextThread ENDP

;
NtSetContextThread PROC
    mov r10, rcx
    mov eax, wrdNtSetContextThread
    jmp QWORD PTR [sysNtSetContextThread]
NtSetContextThread ENDP
;
NtResumeThread PROC
    mov r10, rcx
    mov eax, wrdNtResumeThread
    jmp QWORD PTR [sysNtResumeThread]
NtResumeThread ENDP
;
NtSuspendThread PROC
    mov r10, rcx
    mov eax, wrdNtSuspendThread
    jmp QWORD PTR [sysNtSuspendThread]
NtSuspendThread ENDP
;
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wrdNtAllocateVirtualMemory
    jmp QWORD PTR [sysNtAllocateVirtualMemory]
NtAllocateVirtualMemory ENDP

END;