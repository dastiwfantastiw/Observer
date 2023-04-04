#include "migrate.h"
#include "log.h"

bool migrate::MigrateDebug(HANDLE processHandle, HANDLE threadHandle)
{
    uint32_t pid = GetProcessId(processHandle);

    uint16_t processMachine = 0;
    uint16_t nativeMachine = 0;

    if (IsWow64Process2(processHandle, &processMachine, &nativeMachine) &&
        IMAGE_FILE_MACHINE_UNKNOWN == processMachine)
    {
        logger::Trace("; Migrate (0x%x): The created process is 64-bit application\n", pid);
        return false;
    }

    char buffer[MAX_PATH];
    if (!GetEnvironmentVariableA("ObserverDllDebugPath", (char*)&buffer, sizeof(buffer)))
    {
        logger::Trace("; Migrate (0x%x): GetEnvironmentVariableA failed with code 0x%08x\n", pid, GetLastError());
        return false;
    }

    logger::Trace("; Migrate (0x%x): Debug Dll path: %s\n", processHandle);

    void* addressDllPath =
        VirtualAllocEx(processHandle, NULL, strlen(buffer) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!addressDllPath)
    {
        logger::Trace("; Migrate (0x%x): VirtualAllocEx failed with code 0x%08x\n", pid, GetLastError());
        return false;
    }

    if (!WriteProcessMemory(processHandle, addressDllPath, buffer, strlen(buffer) + 1, NULL))
    {
        logger::Trace("; Migrate (0x%x): WriteProcessMemory failed with code 0x%08x\n", pid, GetLastError());
        return false;
    }

    if (QueueUserAPC((PAPCFUNC)LoadLibraryA, threadHandle, (ULONG_PTR)addressDllPath))
    {
        logger::Trace("; Migrate (0x%x): Successfully (0x%08x)\n", pid, GetLastError());
        return true;
    }

    logger::Trace("; Migrate (0x%x): QueueUserAPC failed with code 0x%08x\n", pid, GetLastError());
    return false;
}

bool migrate::Migrate(HANDLE processHandle, HANDLE threadHandle, inject::ObserverDllData* injectData)
{
    uint32_t pid = GetProcessId(processHandle);

    uint16_t processMachine = 0;
    uint16_t nativeMachine = 0;

    if (IsWow64Process2(processHandle, &processMachine, &nativeMachine) &&
        IMAGE_FILE_MACHINE_UNKNOWN == processMachine)
    {
        logger::Trace("; Migrate (0x%x): The created process is 64-bit application\n", pid);
        return false;
    }

    HANDLE diplicatedHandle = INVALID_HANDLE_VALUE;

    if (!DuplicateHandle(GetCurrentProcess(), injectData->BinConfig->MapHandle, processHandle, &diplicatedHandle, NULL, false, DUPLICATE_SAME_ACCESS))
    {
        logger::Trace("; Migrate (0x%x): DuplicateHandle failed with code 0x%08x\n", pid, GetLastError());
        return false;
    }

    std::vector<uint8_t> dupConfig((uint8_t*)injectData->BinConfig, (uint8_t*)injectData->BinConfig + injectData->BinConfig->Header.Size);

    ((config::BinaryConfig*)(dupConfig.data()))->MapHandle = diplicatedHandle;

    IMAGE_DOS_HEADER* dllImage = (IMAGE_DOS_HEADER*)MapViewOfFile(injectData->BinConfig->MapHandle, FILE_MAP_READ, NULL, NULL, NULL);

    if (dllImage)
    {
        if (dllImage->e_magic != IMAGE_DOS_SIGNATURE)
        {
            logger::Trace("; Migrate (0x%x): Invalid IMAGE_DOS_SIGNATURE\n", pid);
            return false;
        }

        IMAGE_NT_HEADERS* ntHeader =
            (IMAGE_NT_HEADERS*)(dllImage->e_lfanew + (uint8_t*)dllImage);

        if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            logger::Trace("; Migrate (0x%x): Invalid IMAGE_NT_SIGNATURE\n", pid);
            return false;
        }

        IMAGE_SECTION_HEADER* secHeader = (IMAGE_SECTION_HEADER*)(ntHeader + 1);

        IMAGE_DOS_HEADER* addressDllImage =
            (IMAGE_DOS_HEADER*)VirtualAllocEx(processHandle, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!addressDllImage)
        {
            logger::Trace("; Migrate (0x%x): VirtualAllocEx failed with code 0x%08x\n", pid, GetLastError());
            return false;
        }

        if (!WriteProcessMemory(processHandle, addressDllImage, dllImage, ntHeader->OptionalHeader.SizeOfHeaders, NULL))
        {
            logger::Trace("; Migrate (0x%x): WriteProcessMemory failed with code 0x%08x\n", pid, GetLastError());
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
                logger::Trace("; Migrate (0x%x): WriteProcessMemory failed with code 0x%08x\n", pid, GetLastError());
                return false;
            }
        }

        IMAGE_DOS_HEADER* addressInjectData =
            (IMAGE_DOS_HEADER*)VirtualAllocEx(processHandle, NULL, sizeof(inject::LdrData) + injectData->LoaderSize + dupConfig.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!addressInjectData)
        {
            logger::Trace("; Migrate (0x%x): VirtualAllocEx failed with code 0x%08x\n", pid, GetLastError());
            return false;
        }

        inject::LdrData ldr = {};

        ldr.ObserverData.LdrData = (inject::LdrData*)addressInjectData;
        ldr.ObserverData.Loader = (inject::Loader)((inject::LdrData*)(addressInjectData) + 1);
        ldr.ObserverData.LoaderSize = injectData->LoaderSize;
        ldr.ObserverData.BinConfig = (config::BinaryConfig*)((uint8_t*)((inject::LdrData*)(addressInjectData) + 1) + ldr.ObserverData.LoaderSize);

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
            logger::Trace("; Migrate (0x%x): WriteProcessMemory failed with code 0x%08x\n", pid, GetLastError());
            return false;
        }

        if (!WriteProcessMemory(processHandle, ldr.ObserverData.Loader, injectData->Loader, ldr.ObserverData.LoaderSize, NULL))
        {
            logger::Trace("; Migrate (0x%x): WriteProcessMemory failed with code 0x%08x\n", pid, GetLastError());
            return false;
        }

        if (!WriteProcessMemory(processHandle, ldr.ObserverData.BinConfig, dupConfig.data(), dupConfig.size(), NULL))
        {
            logger::Trace("; Migrate (0x%x): WriteProcessMemory failed with code 0x%08x\n", pid, GetLastError());
            return false;
        }

        if (QueueUserAPC((PAPCFUNC)ldr.ObserverData.Loader, threadHandle, (ULONG_PTR)ldr.ObserverData.LdrData))
        {
            logger::Trace("; Migrate (0x%x): Successfully (0x%08x)\n", pid, GetLastError());
            return true;
        }

        logger::Trace("; Migrate (0x%x): QueueUserAPC failed with code 0x%08x\n", pid, GetLastError());
    }
    return false;
}
