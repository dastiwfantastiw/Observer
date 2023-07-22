#include "inject.h"
#include "loader.h"

#ifdef _DEBUG
bool CRemoteThreadInjection::Inject(HANDLE hProcess, HANDLE hThread, void* data, uint32_t dataSize, CConfig config)
{
    uint16_t processMachine = 0;
    uint16_t nativeMachine = 0;

    if (IsWow64Process2(hProcess, &processMachine, &nativeMachine) &&
        IMAGE_FILE_MACHINE_UNKNOWN == processMachine)
    {
        printf("[-] Created process is 64-bit application\n");
        return false;
    }

    char* _strDllPath = (char*)VirtualAllocEx(hProcess, NULL, dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!_strDllPath)
    {
        printf("[-] VirtualAllocEx failed (0x%08x)\n", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(hProcess, _strDllPath, data, dataSize, NULL))
    {
        printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
        return false;
    }

    HANDLE threadHandle = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)(LoadLibraryA), _strDllPath, NULL, NULL);
    if (threadHandle == INVALID_HANDLE_VALUE || threadHandle == NULL)
    {
        printf("[-] CreateRemoteThread failed (0x%08x)\n", GetLastError());
        return false;
    }

    WaitForSingleObject(threadHandle, INFINITE);
    return ResumeThread(hThread);
}
#endif

bool CReflectiveThreadInjection::Inject(HANDLE hProcess, HANDLE hThread, void* data, uint32_t dataSize, CConfig config)
{
    uint16_t processMachine = 0;
    uint16_t nativeMachine = 0;

    if (IsWow64Process2(hProcess, &processMachine, &nativeMachine) &&
        IMAGE_FILE_MACHINE_UNKNOWN == processMachine)
    {
        printf("[-] Created process is 64-bit application\n");
        return false;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((uint8_t*)dosHeader + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* secHeader = (IMAGE_SECTION_HEADER*)(ntHeaders + 1);

    IMAGE_DOS_HEADER* _dllImage = (IMAGE_DOS_HEADER*)VirtualAllocEx(hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // allocate memory for dll image

    if (!_dllImage)
    {
        printf("[-] VirtualAllocEx failed (0x%08x)\n", GetLastError());
        return false;
    }

    printf("[+] Image address: 0x%08x\n", (uint32_t)_dllImage);

    if (!WriteProcessMemory(hProcess, _dllImage, dosHeader, ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) // write headers
    {
        printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
        return false;
    }

    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) // copy sections
    {
        if (!WriteProcessMemory(
                hProcess,
                (void*)((uint8_t*)_dllImage + secHeader[i].VirtualAddress),
                (void*)((uint8_t*)dosHeader + secHeader[i].PointerToRawData),
                secHeader[i].SizeOfRawData,
                NULL))
        {
            printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
            return false;
        }

        printf("[+] [%d] Section address: 0x%08x\n", i, (uint32_t)((uint8_t*)_dllImage + secHeader[i].VirtualAddress));
    }

    if (!DuplicateHandle(GetCurrentProcess(), config.m_DllHandle, hProcess, &config.m_DllHandle, NULL, false, DUPLICATE_SAME_ACCESS)) // duplicate handle for the target process
    {
        printf("[-] DuplicateHandle failed (0x%08x)\n", GetLastError());
        return false;
    }

    CBinaryConfig binaryConfig;

    config.ToBinary(binaryConfig); // converting to binary format

    uint8_t shellcodeLoader[] = "\x60\xE8\x00\x00\x00\x00\x5B\x81\xEB\x06\x00\x00\x00\xB8\xCC\xCC\xCC\xCC\xBA\xCC\xCC\xCC\xCC\x52\xFF\xD0\x61\x68\xCC\xCC\xCC\xCC\xC3";

    uint8_t* _injectData = (uint8_t*)VirtualAllocEx(hProcess, // memory for inject data
                                                    NULL,
                                                    sizeof(LdrData) + ((uint32_t)LoaderDllEnd - (uint32_t)LoaderDll) + binaryConfig.size() + sizeof(shellcodeLoader),
                                                    MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_EXECUTE_READWRITE);

    if (!_injectData)
    {
        printf("[-] VirtualAllocEx failed (0x%08x)\n", GetLastError());
        return false;
    }

    LdrData ldr = {}; // preparing LdrData

    ldr.fGetProcAddress = GetProcAddress;
    ldr.fLoadLibraryA = LoadLibraryA;

    ldr.ImageBase = _dllImage;
    ldr.ImageNtHeader = (IMAGE_NT_HEADERS*)((uint8_t*)_dllImage + dosHeader->e_lfanew);
    ldr.ImageImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)_dllImage + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ldr.ImageBaseReloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)_dllImage + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    ldr.ObserverInjectData.LdrData = (LdrData*)_injectData;
    ldr.ObserverInjectData.Loader = (pLoader)((LdrData*)(_injectData) + 1);
    ldr.ObserverInjectData.LoaderSize = (uint32_t)LoaderDllEnd - (uint32_t)LoaderDll;
    ldr.ObserverInjectData.BinaryConfig = (CBinaryConfig*)((uint8_t*)((LdrData*)(_injectData) + 1) + ldr.ObserverInjectData.LoaderSize);
    ldr.ObserverInjectData.BinaryConfigSize = binaryConfig.size();

    // write into the memory

    if (!WriteProcessMemory(hProcess, ldr.ObserverInjectData.LdrData, &ldr, sizeof(ldr), NULL)) //1. LdrData
    {
        printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
        return false;
    }
    printf("[+] Loader data address: 0x%08x\n", (uint32_t)ldr.ObserverInjectData.LdrData);

    if (!WriteProcessMemory(hProcess, ldr.ObserverInjectData.Loader, LoaderDll, ldr.ObserverInjectData.LoaderSize, NULL)) //2. Loader code
    {
        printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
        return false;
    }
    printf("[+] Loader address: 0x%08x (%d bytes)\n", (uint32_t)ldr.ObserverInjectData.Loader, ldr.ObserverInjectData.LoaderSize);

    if (!WriteProcessMemory(hProcess, ldr.ObserverInjectData.BinaryConfig, binaryConfig.data(), binaryConfig.size(), NULL)) //3. Binary config
    {
        printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
        return false;
    }
    printf("[+] Binary config: 0x%08x (%d bytes)\n", (uint32_t)ldr.ObserverInjectData.BinaryConfig, binaryConfig.size());

    // get thread context

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx))
    {
        printf("[-] GetThreadContext failed (0x%08x)\n", GetLastError());
        return false;
    }

    // preparing shellcode data

    *(void**)(shellcodeLoader + 0x1c) = (uint32_t*)ctx.Eip;
    *(void**)(shellcodeLoader + 0xe) = ldr.ObserverInjectData.Loader;
    *(void**)(shellcodeLoader + 0x13) = ldr.ObserverInjectData.LdrData;

    ctx.Eip = (DWORD)((uint8_t*)ldr.ObserverInjectData.BinaryConfig + binaryConfig.size() + 1);

    if (!WriteProcessMemory(hProcess, (uint8_t*)ctx.Eip, &shellcodeLoader, sizeof(shellcodeLoader), NULL)) //4. Code
    {
        printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
        return false;
    }

    printf("[+] ShellLoader address: 0x%08x\n", (uint32_t)ctx.Eip);

    SetThreadContext(hThread, &ctx);
    FlushInstructionCache(hProcess, 0, 0);
    return ResumeThread(hThread);
}
