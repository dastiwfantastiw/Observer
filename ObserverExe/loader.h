#pragma once
#include "loader_data.h"

struct LdrData
{
    pLoadLibraryA fLoadLibraryA;
    pGetProcAddress fGetProcAddress;

    IMAGE_DOS_HEADER* ImageBase;
    IMAGE_NT_HEADERS* ImageNtHeader;
    IMAGE_BASE_RELOCATION* ImageBaseReloc;
    IMAGE_IMPORT_DESCRIPTOR* ImageImportDesc;

    InjectData ObserverInjectData;
};

inline DWORD WINAPI LoaderDll(LdrData* data)
{
    IMAGE_BASE_RELOCATION* baseReloc = data->ImageBaseReloc;

    DWORD delta = (DWORD)((uint8_t*)data->ImageBase - data->ImageNtHeader->OptionalHeader.ImageBase);

    while (baseReloc->VirtualAddress)
    {
        if (baseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            int count = (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)(baseReloc + 1);

            for (int i = 0; i < count; i++)
            {
                if (list[i])
                {
                    DWORD* ptr = (DWORD*)((uint8_t*)data->ImageBase + (baseReloc->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }

        baseReloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)baseReloc + baseReloc->SizeOfBlock);
    }

    IMAGE_IMPORT_DESCRIPTOR* importDesc = data->ImageImportDesc;

    while (importDesc->Characteristics)
    {
        PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((uint8_t*)data->ImageBase + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((uint8_t*)data->ImageBase + importDesc->FirstThunk);

        HMODULE hModule = data->fLoadLibraryA((LPCSTR)data->ImageBase + importDesc->Name);

        if (!hModule)
        {
            return 1;
        }

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                DWORD Function = (DWORD)data->fGetProcAddress(hModule, reinterpret_cast<char*>(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                {
                    return 1;
                }

                FirstThunk->u1.Function = Function;
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME imageByName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)data->ImageBase + OrigFirstThunk->u1.AddressOfData);
                DWORD Function = (DWORD)data->fGetProcAddress(hModule, (LPCSTR)imageByName->Name);
                if (!Function)
                {
                    return 1;
                }

                FirstThunk->u1.Function = Function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        importDesc++;
    }

    if (data->ImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)((uint8_t*)data->ImageBase + data->ImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; callbacks && *callbacks; ++callbacks)
        {
            (*callbacks)((uint8_t*)data->ImageBase, DLL_PROCESS_ATTACH, NULL);
        }
    }

    if (data->ImageNtHeader->OptionalHeader.AddressOfEntryPoint)
    {
        dllMain EntryPoint = (dllMain)((uint8_t*)data->ImageBase + data->ImageNtHeader->OptionalHeader.AddressOfEntryPoint);

        return EntryPoint((HMODULE)data->ImageBase, DLL_PROCESS_ATTACH, &data->ObserverInjectData);
    }

    return 0;
}

inline DWORD WINAPI LoaderDllEnd()
{
    return 0x1337;
}
