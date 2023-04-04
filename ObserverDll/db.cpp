#include "db.h"

#include <winternl.h>

#include <algorithm>
#include <filesystem>
#include <set>
#include <string>

#include "../Observer/hash.h"

#include "events.h"

namespace db {
std::map<uint32_t, std::map<uint32_t, eventHandler>> dbEvents = {
    {0x066b021f,
     {std::make_pair(0x49ce0795, OnCreateUserProcess),
      std::make_pair(0x23500534, OnOpenProcess),
      std::make_pair(0x6c930948, OnAllocateVirtualMemory),
      std::make_pair(0x65f10904, OnProtectVirtualMemory),
      std::make_pair(0x49e4079f, OnReadVirtualMemory),
      std::make_pair(0x5450082e, OnWriteVirtualMemory),
      std::make_pair(0x826a09b0, OnWow64ReadVirtualMemory64),
      std::make_pair(0x8f9b0a3f, OnWow64WriteVirtualMemory64),
      std::make_pair(0x144703bf, OnReadFile),
      std::make_pair(0x19ac044e, OnWriteFile),
      std::make_pair(0x1d600497, OnCreateFile),
      std::make_pair(0x14c603d5, OnOpenFile),
      std::make_pair(0x586c082c, OnDeviceIoControlFile),
      std::make_pair(0x18dd0440, OnCreateKey),
      std::make_pair(0x18c7043f, OnDeleteKey),
      std::make_pair(0x33f1063c, OnDeleteValueKey),
      std::make_pair(0x22ea0515, OnSetValueKey),
      std::make_pair(0x2f7e05ff, OnQueryValueKey),
      std::make_pair(0x291b0592, OnEnumerateKey),
      std::make_pair(0x42680720, OnGetContextThread),
      std::make_pair(0x4328072c, OnSetContextThread)}}};
}

bool db::GetSyscallFromModule(IMAGE_DOS_HEADER* image,
                              std::map<uint32_t, DbFunction>& db,
                              config::ModuleData& moduleData,
                              std::map<uint32_t, config::FunctionData>& funcs)
{
    IMAGE_NT_HEADERS* ntHeader =
        (IMAGE_NT_HEADERS*)((uint8_t*)image + image->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    uint32_t exportSize =
        ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (!exportSize)
    {
        return false;
    }

    IMAGE_EXPORT_DIRECTORY* exportDir =
        (IMAGE_EXPORT_DIRECTORY*)(ntHeader->OptionalHeader
                                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                      .VirtualAddress +
                                  (uint8_t*)image);

    uint32_t* addressOfFunction =
        (uint32_t*)(exportDir->AddressOfFunctions + (uint8_t*)image);
    uint16_t* addressONameOrdinals =
        (uint16_t*)(exportDir->AddressOfNameOrdinals + (uint8_t*)image);
    uint32_t* addressONames =
        (uint32_t*)(exportDir->AddressOfNames + (uint8_t*)image);

    std::set<uint32_t> excludedIds;

    for (uint32_t i = 0; i < (exportDir->NumberOfNames); i++)
    {
        uint8_t* funcAddress =
            (uint8_t*)((uint8_t*)image + addressOfFunction[addressONameOrdinals[i]]);

        if ((DWORD)funcAddress >= (DWORD)exportDir &&
            (DWORD)funcAddress < (DWORD)(exportDir + exportSize))
        {
            continue;
        }

        if (funcAddress[0] == 0xB8)
        {
            std::string funcName = (char*)(addressONames[i] + (uint8_t*)image);
            uint32_t funcHash =
                adler32((const unsigned char*)funcName.c_str(), funcName.length());

            uint32_t argc = -1;
            uint32_t id = *(uint32_t*)&(funcAddress[1]);

            for (uint32_t i = 5; i < 32; i++)
            {
                if (funcAddress[i] == 0xc3)
                {
                    argc = 0;
                    break;
                }

                if (funcAddress[i] == 0xc2)
                {
                    argc = ((uint16_t)funcAddress[i + 1]) / 4;
                    break;
                }
            }

            if (excludedIds.contains(id) || argc == -1)
            {
                continue;
            }

            eventHandler eventFunction = NULL;

            if (funcs.contains(funcHash))
            {
                config::FunctionData func = funcs[funcHash];

                if (funcHash == func.FuncHash)
                {
                    if (func.Enabled)
                    {
                        if (func.EventsEnabled)
                        {
                            if (dbEvents.contains(moduleData.ModuleHash) && dbEvents[moduleData.ModuleHash].contains(func.FuncHash))
                            {
                                eventFunction = dbEvents[moduleData.ModuleHash][func.FuncHash];
                            }
                        }

                        db.insert(std::pair<uint32_t, DbFunction>(
                            id,
                            {funcName, funcHash, argc, func.Mode, func.Types, func.MaxPtr, func.MinStrLen, func.MaxStrLen, func.EventsEnabled, eventFunction}));
                    }
                    else
                    {
                        excludedIds.insert(id);
                    }
                }
            }
            else if (moduleData.EnabledAll)
            {
                if (moduleData.EventsEnabledAll)
                {
                    if (dbEvents.contains(moduleData.ModuleHash) && dbEvents[moduleData.ModuleHash].contains(funcHash))
                    {
                        eventFunction = dbEvents[moduleData.ModuleHash][funcHash];
                    }
                }

                db.insert(std::pair<uint32_t, DbFunction>(
                    id,
                    {funcName, funcHash, argc, moduleData.ModeAll, moduleData.TypeAll, moduleData.MaxPtrAll, moduleData.MinStrLenAll, moduleData.MaxStrLenAll, moduleData.EventsEnabledAll, eventFunction}));
            }
        }
    }

    return false;
}

IMAGE_DOS_HEADER* db::FindModule(uint32_t hash)
{
    PEB_LDR_DATA* ldrData = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;

    PLIST_ENTRY head = ldrData->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY next = head;

    do
    {
        PLDR_DATA_TABLE_ENTRY pldrEntry =
            CONTAINING_RECORD(head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (!pldrEntry->DllBase)
        {
            head = pldrEntry->InMemoryOrderLinks.Flink;
            continue;
        }

        std::filesystem::path modulePath(pldrEntry->FullDllName.Buffer);
        std::string moduleName = modulePath.stem().string();
        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

        if (adler32((const unsigned char*)moduleName.c_str(),
                    moduleName.length()) == hash)
        {
            return (IMAGE_DOS_HEADER*)pldrEntry->DllBase;
        }

        head = pldrEntry->InMemoryOrderLinks.Flink;
    } while (head != next);

    return NULL;
}
