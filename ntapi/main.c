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
#define STATUS_SUCCESS 0x00000000
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SPECIFIC_RIGHTS_ALL)

size_t GetModHandle(wchar_t *ln) {
	PEB* pPeb = (PEB*)__readgsqword(0x60);
	PLIST_ENTRY header = &(pPeb->Ldr->InMemoryOrderModuleList);
	i("%p\n",pPeb);
	i("%p\n", header);



	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
		i("%p", curr);
		LDR_DATA_TABLE_ENTRY* data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		i("current node is: %ls\n", data->FullDllName.Buffer);

		if (StrStrIW(ln, data->FullDllName.Buffer)) {
			e("%ls is a match to %ls.", data->FullDllName.Buffer,ln);

			return data->DllBase;
		}
		else {
			e("%ls is not a match to %ls\n" , data->FullDllName.Buffer,ln);
		}


	}
	e("returning NULL value, failed to get dll");
	return 0;

}

size_t GetFuncAddr(size_t modb, char* fn) {

	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY data_Dir = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(modb + data_Dir.VirtualAddress);

	i("Export Table: %p\n", exportTable);
	DWORD* arrf = (DWORD *)(modb + exportTable->AddressOfFunctions);
	DWORD* arrn = (DWORD*)(modb + exportTable->AddressOfNames);
	DWORD* arrno = (DWORD*)(modb + exportTable->AddressOfNameOrdinals);

	for (size_t i = 0; i < exportTable->NumberOfNames; i++) {
		char* name = (char*)(modb + arrn[i]);
		WORD numCAPIO = arrno[i] + 1;
		if (!stricmp(name, fn)) {
			g("Found ordinal %.4x - %s\n",numCAPIO, name);
			return modb + arrf[numCAPIO - 1];

		}

	}


	return 0;


}




int main(int argc, char** argv, char* envp) {
	size_t kb = GetModHandle(L"C:\\WINDOWS\\System32\\ntdll.dll");
	g(" GetModHandle(ntdll.dll) = % p\n", kb);

	size_t ptr_NtOpenThread = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_NtSuspendThreat = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_NtGetContextThread = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_AllocateVirtualMemory = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_NtWriteVirtualMemory = (size_t)GetFuncAddr(kb,L"NtOpenThread");



	NTSTATUS status;

	STARTUPINFO si;
	HANDLE hThread;
	HANDLE hProc;
	OBJECT_ATTRIBUTES oa;




	status = ((NTSTATUS(NTAPI*)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG))ptr_NtOpenThread)(hThread, THREAD_ALL_ACCESS, &oa ,0);


	return 0;
}