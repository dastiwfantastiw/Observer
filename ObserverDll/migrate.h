#pragma once
#include "loader.h"

class CMigrate
{
private:
    CLogger& m_Logger;

public:
    CMigrate(CLogger& logger)
        : m_Logger(logger){};

    bool Migrate(HANDLE hProcess, HANDLE hThread, CConfig config)
    {
        m_Logger.Trace("; Migration(0x%08x, 0x%08x, mapDllHandle=0x%08x) started:\n", hProcess, hThread, config.m_DllHandle);
        uint16_t processMachine = 0;
        uint16_t nativeMachine = 0;

        if (IsWow64Process2(hProcess, &processMachine, &nativeMachine) &&
            IMAGE_FILE_MACHINE_UNKNOWN == processMachine)
        {
            m_Logger.Trace("; The created process is 64-bit application\n");
            return false;
        }

        IMAGE_DOS_HEADER* dllImage = (IMAGE_DOS_HEADER*)MapViewOfFile(config.m_DllHandle, FILE_MAP_READ, NULL, NULL, NULL);

        if (!dllImage)
        {
            m_Logger.Trace("; MapViewOfFile failed with code (0x%08x)\n", GetLastError());
            return false;
        }

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllImage;
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((uint8_t*)dosHeader + dosHeader->e_lfanew);
        IMAGE_SECTION_HEADER* secHeader = (IMAGE_SECTION_HEADER*)(ntHeaders + 1);

        IMAGE_DOS_HEADER* _dllImage = (IMAGE_DOS_HEADER*)VirtualAllocEx(hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // allocate memory for dll image

        if (!_dllImage)
        {
            m_Logger.Trace("; VirtualAllocEx failed with code (0x%08x)\n", GetLastError());
            return false;
        }

        if (!WriteProcessMemory(hProcess, _dllImage, dosHeader, ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) // write headers
        {
            m_Logger.Trace("; WriteProcessMemory failed with code (0x%08x)\n", GetLastError());
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
                m_Logger.Trace("; WriteProcessMemory failed with code (0x%08x)\n", GetLastError());
                return false;
            }
        }

        if (!DuplicateHandle(GetCurrentProcess(), config.m_DllHandle, hProcess, &config.m_DllHandle, NULL, false, DUPLICATE_SAME_ACCESS)) // duplicate handle for the target process
        {
            m_Logger.Trace("; DuplicateHandle failed with code (0x%08x)\n", GetLastError());
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
            m_Logger.Trace("; VirtualAllocEx failed with code (0x%08x)\n", GetLastError());
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
            m_Logger.Trace("; WriteProcessMemory failed with code (0x%08x)\n", GetLastError());
            return false;
        }

        if (!WriteProcessMemory(hProcess, ldr.ObserverInjectData.Loader, LoaderDll, ldr.ObserverInjectData.LoaderSize, NULL)) //2. Loader code
        {
            m_Logger.Trace("; WriteProcessMemory failed with code (0x%08x)\n", GetLastError());
            return false;
        }

        if (!WriteProcessMemory(hProcess, ldr.ObserverInjectData.BinaryConfig, binaryConfig.data(), binaryConfig.size(), NULL)) //3. Binary config
        {
            m_Logger.Trace("; WriteProcessMemory failed with code (0x%08x)\n", GetLastError());
            return false;
        }

        // get thread context

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(hThread, &ctx))
        {
            m_Logger.Trace("; GetThreadContext failed with code (0x%08x)\n", GetLastError());
            return false;
        }

        // preparing shellcode data

        *(void**)(shellcodeLoader + 0x1c) = (uint32_t*)ctx.Eip;
        *(void**)(shellcodeLoader + 0xe) = ldr.ObserverInjectData.Loader;
        *(void**)(shellcodeLoader + 0x13) = ldr.ObserverInjectData.LdrData;

        ctx.Eip = (DWORD)((uint8_t*)ldr.ObserverInjectData.BinaryConfig + binaryConfig.size() + 1);

        if (!WriteProcessMemory(hProcess, (uint8_t*)ctx.Eip, &shellcodeLoader, sizeof(shellcodeLoader), NULL)) //4. Code
        {
            m_Logger.Trace("; WriteProcessMemory failed with code (0x%08x)\n", GetLastError());
            return false;
        }

        SetThreadContext(hThread, &ctx);
        FlushInstructionCache(hProcess, 0, 0);
        m_Logger.Trace("; Migration(0x%08x, 0x%08x) ended\n", hProcess, hThread);
        return ResumeThread(hThread);
    }
};
