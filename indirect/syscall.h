#ifndef _SYSCALLS_H
#define _SYSCALLS_H
#include <windows.h>
#include "main.h"

DWORD wrdNtSuspendThread;
DWORD wrdNtAllocateVirtualMemory;
DWORD wrdNtWriteVirtualMemory;
DWORD wrdNtOpenThread;
DWORD wrdNtOpenProcess;
DWORD wrdNtGetContextThread;
DWORD wrdNtSetContextThread;
DWORD wrdNtResumeThread;

UINT_PTR sysNtSuspendThread;
UINT_PTR sysNtAllocateVirtualMemory;
UINT_PTR sysNtWriteVirtualMemory;
UINT_PTR sysNtOpenThread;
UINT_PTR sysNtOpenProcess;
UINT_PTR sysNtGetContextThread;
UINT_PTR sysNtSetContextThread;
UINT_PTR sysNtResumeThread;

typedef long NTSTATUS;
typedef NTSTATUS* PNTSTATUS;

#ifdef __cplusplus   
extern "C" {        
#endif


extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,    
    PVOID* BaseAddress,      
    ULONG_PTR ZeroBits,      
    PSIZE_T RegionSize,      
    ULONG AllocationType,    
    ULONG Protect            
);

extern NTSTATUS NtSuspendThread(
    HANDLE ThreadHandle,     
    PULONG PreviousSuspendCount 
);

extern NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,     
    PVOID BaseAddress,      
    PVOID Buffer,             
    SIZE_T NumberOfBytesToWrite, 
    PULONG NumberOfBytesWritten 
);

extern NTSTATUS NtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId

);

extern NTSTATUS NtOpenProcess(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);



extern NTSTATUS NtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);
extern NTSTATUS NtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

extern NTSTATUS NtResumeThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

#ifdef __cplusplus  
}
#endif
#endif // _SYSCALLS_H