#include "inject.h"

using namespace config;

namespace inject {

bool ReflectiveThreadHijackingInject(
    HANDLE processHandle, HANDLE threadHandle, HANDLE dllDuplicatedHandle, IMAGE_DOS_HEADER* dllImage, BinaryConfig* config)
{
    if (!dllImage || !config)
    {
        printf("\n\t[-] Error: There are no dllImage or config\n");
        return false;
    }

    if (dllImage->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\n\t[-] Error: Invalid IMAGE_DOS_SIGNATURE\n");
        return false;
    }

    IMAGE_NT_HEADERS* ntHeader =
        (IMAGE_NT_HEADERS*)(dllImage->e_lfanew + (uint8_t*)dllImage);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("\n\t[-] Error: Invalid IMAGE_NT_SIGNATURE\n");
        return false;
    }

    IMAGE_SECTION_HEADER* secHeader = (IMAGE_SECTION_HEADER*)(ntHeader + 1);

    IMAGE_DOS_HEADER* addressDllImage =
        (IMAGE_DOS_HEADER*)VirtualAllocEx(processHandle, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!addressDllImage)
    {
        printf("\n\t[-] Error: VirtualAllocEx failed (0x%08x)\n", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(processHandle, addressDllImage, dllImage, ntHeader->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("\n\t[-] Error: WriteProcessMemory failed (0x%08x)\n",
               GetLastError());
        return false;
    }

    for (uint32_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        if (!WriteProcessMemory(
                processHandle,
                (void*)((uint8_t*)addressDllImage + secHeader[i].VirtualAddress),
                (void*)((uint8_t*)dllImage + secHeader[i].PointerToRawData),
                secHeader[i].SizeOfRawData,
                NULL))
        {
            printf("\n\t[-] Error: WriteProcessMemory failed (0x%08x)\n",
                   GetLastError());
            return false;
        }
    }

    config->MapHandle = dllDuplicatedHandle;

    uint8_t code[] =
        "\x60\xE8\x00\x00\x00\x00\x5B\x81\xEB\x06\x00\x00\x00\xB8\xCC\xCC\xCC"
        "\xCC\xBA\xCC\xCC\xCC\xCC\x52\xFF\xD0\x61\x68\xCC\xCC\xCC\xCC\xC3";

    //1. LdrData
    //2. Loader code
    //3. Binary config
    //4. Code

    void* addressInjectData =
        VirtualAllocEx(processHandle, NULL, sizeof(LdrData) + ((uint32_t)inject::LoaderDllEnd - (uint32_t)inject::LoaderDll) + config->Header.Size + sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!addressInjectData)
    {
        printf("\n\t[-] Error: VirtualAllocEx failed (0x%08x)\n", GetLastError());
        return false;
    }

    LdrData ldr = {};

    ldr.ObserverData.LdrData = (LdrData*)addressInjectData;
    ldr.ObserverData.Loader = (Loader)((LdrData*)(addressInjectData) + 1);
    ldr.ObserverData.LoaderSize = (uint32_t)inject::LoaderDllEnd - (uint32_t)inject::LoaderDll;
    ldr.ObserverData.BinConfig = (config::BinaryConfig*)((uint8_t*)((LdrData*)(addressInjectData) + 1) + ldr.ObserverData.LoaderSize);

    ldr.fGetProcAddress = GetProcAddress;
    ldr.fLoadLibraryA = LoadLibraryA;

    ldr.ImageBase = addressDllImage;
    ldr.ImageBaseReloc =
        (IMAGE_BASE_RELOCATION*)((uint8_t*)addressDllImage +
                                 ntHeader->OptionalHeader
                                     .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                     .VirtualAddress);
    ldr.ImageImportDesc =
        (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)addressDllImage +
                                   ntHeader->OptionalHeader
                                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                       .VirtualAddress);
    ldr.ImageNtHeader =
        (IMAGE_NT_HEADERS*)((uint8_t*)addressDllImage + dllImage->e_lfanew);

    if (!WriteProcessMemory(processHandle, ldr.ObserverData.LdrData, &ldr, sizeof(ldr), NULL))
    {
        printf("\n\t[-] Error: WriteProcessMemory failed (0x%08x)\n",
               GetLastError());
        return false;
    }

    if (!WriteProcessMemory(processHandle, ldr.ObserverData.Loader, inject::LoaderDll, ldr.ObserverData.LoaderSize, NULL))
    {
        printf("\n\t[-] Error: WriteProcessMemory failed (0x%08x)\n",
               GetLastError());
        return false;
    }

    if (!WriteProcessMemory(processHandle, ldr.ObserverData.BinConfig, config, config->Header.Size, NULL))
    {
        printf("\n\t[-] Error: WriteProcessMemory failed (0x%08x)\n",
               GetLastError());
        return false;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(threadHandle, &ctx);

    *(void**)(code + 0x1c) = (uint32_t*)ctx.Eip;
    *(void**)(code + 0xe) = ldr.ObserverData.Loader;
    *(void**)(code + 0x13) = ldr.ObserverData.LdrData;

    ctx.Eip = (DWORD)((uint8_t*)ldr.ObserverData.BinConfig + config->Header.Size + 1);

    if (!WriteProcessMemory(processHandle, (uint8_t*)ctx.Eip, &code, sizeof(code), NULL))
    {
        printf("\n\t[-] Error: WriteProcessMemory failed (0x%08x)\n",
               GetLastError());
        return false;
    }

    SetThreadContext(threadHandle, &ctx);
    return FlushInstructionCache(processHandle, 0, 0);
}

bool LoadLibraryInject(HANDLE processHandle, std::string& dllPath)
{
    void* addressDllPath =
        VirtualAllocEx(processHandle, NULL, dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!addressDllPath)
    {
        printf("\n\t[-] Error: VirtualAllocEx failed (0x%08x)\n", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(processHandle, addressDllPath, dllPath.data(), dllPath.length(), NULL))
    {
        printf("\n\t[-] Error: WriteProcessMemory failed (0x%08x)\n",
               GetLastError());
        return false;
    }

    HANDLE hThread = CreateRemoteThread(processHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)(LoadLibraryA), addressDllPath, NULL, NULL);

    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL)
    {
        printf("\n\t[-] Error: CreateRemoteThread failed (0x%08x)\n",
               GetLastError());
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    return true;
}
} // namespace inject