#include "database.h"

bool CDataBase::Init(CConfig* config)
{
    for (auto m = config->m_Modules.begin(); m != config->m_Modules.end(); m++)
    {
        if (m->second.m_IsEnabled)
        {
            CDbModule mod(m_Logger, m->second);

            if (PEBFindModule(m->first, mod))
            {
                if (ModuleInitSyscalls(mod, m_DbModulesEvents.contains(m->first) ? &m_DbModulesEvents[m->first] : NULL))
                {
                    m_DbModules.insert(std::pair<uint32_t, CDbModule>(m->first, mod));
                }
            }
            else
            {
                m_DbWaitModules.insert(std::pair<uint32_t, CModule>(m->first, m->second));
            }
        }
    }
    return !m_DbModules.empty();
}

bool CDataBase::IsFunctionExists(uint32_t id, CDbModule*& module, CDbFunction*& func)
{
    for (auto m = m_DbModules.begin(); m != m_DbModules.end(); m++)
    {
        if (m->second.m_DbFunctions.contains(id))
        {
            module = &m->second;
            func = &m->second.m_DbFunctions[id];
            return true;
        }
    }
    return false;
}

int CDataBase::CheckWaitList()
{
    if (m_DbWaitModules.empty())
        return -1;

    int k = 0;

    auto m = m_DbWaitModules.begin();

    for (; m != m_DbWaitModules.end();)
    {
        if (m->second.m_IsEnabled)
        {
            CDbModule mod(m_Logger, m->second);

            if (PEBFindModule(m->first, mod))
            {
                if (ModuleInitSyscalls(mod, m_DbModulesEvents.contains(m->first) ? &m_DbModulesEvents[m->first] : NULL))
                {
                    m_DbModules.insert(std::pair<uint32_t, CDbModule>(m->first, mod));
                    k++;
                    m_DbWaitModules.erase(m);
                }
            }
        }
        m++;
    }
    return k;
}

bool CDataBase::PEBFindModule(uint32_t hash, CDbModule& module)
{
    PEB_LDR_DATA* ldrData = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;

    PLIST_ENTRY head = ldrData->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY next = head;

    do
    {
        PLDR_DATA_TABLE_ENTRY pldrEntry = CONTAINING_RECORD(head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (!pldrEntry->DllBase)
        {
            head = pldrEntry->InMemoryOrderLinks.Flink;
            continue;
        }

        std::filesystem::path stemModuleName(pldrEntry->FullDllName.Buffer);

        std::string moduleName = stemModuleName.stem().string();
        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

        if (adler32(moduleName.c_str(),
                    moduleName.length()) == hash)
        {
            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pldrEntry->DllBase;

            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((uint8_t*)dosHeader + dosHeader->e_lfanew);

            if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
                return false;

            if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
            {
                module.m_ImageExportAddress = (IMAGE_EXPORT_DIRECTORY*)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (uint8_t*)dosHeader);
                module.m_ImageExportSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }

            module.m_Name = moduleName;
            module.m_ImageAddress = dosHeader;
            return true;
        }

        head = pldrEntry->InMemoryOrderLinks.Flink;
    } while (head != next);

    return false;
}

bool CDataBase::ModuleInitSyscalls(CDbModule& module, DbEventsContainer* dbEvents)
{
    if (!module.m_ImageExportAddress)
        return false;

    uint32_t* addressOfFunction = (uint32_t*)(module.m_ImageExportAddress->AddressOfFunctions + (uint8_t*)module.m_ImageAddress);
    uint16_t* addressONameOrdinals = (uint16_t*)(module.m_ImageExportAddress->AddressOfNameOrdinals + (uint8_t*)module.m_ImageAddress);
    uint32_t* addressONames = (uint32_t*)(module.m_ImageExportAddress->AddressOfNames + (uint8_t*)module.m_ImageAddress);

    for (uint32_t i = 0; i < module.m_ImageExportAddress->NumberOfNames; i++)
    {
        uint8_t* funcAddress = (uint8_t*)((uint8_t*)module.m_ImageAddress + addressOfFunction[addressONameOrdinals[i]]);

        if ((uint32_t)funcAddress >= (uint32_t)module.m_ImageExportAddress &&
            (uint32_t)funcAddress < (uint32_t)(module.m_ImageExportAddress + module.m_ImageExportSize))
            continue;

        uint32_t id = 0;
        int8_t argc = -1;

        if (IsSyscall(funcAddress, id, argc))
        {
            if (module.m_DbFunctions.contains(id) || module.m_DbDisabledFuncId.contains(id))
                continue;

            std::string funcName = (char*)((uint8_t*)module.m_ImageAddress + addressONames[i]);
            uint32_t funcHash = adler32(funcName.c_str(), funcName.length());

            if (module.m_Functions.contains(funcHash) && !module.m_DbDisabledFuncId.contains(id))
            {
                if (module.m_Functions[funcHash].m_IsEnabled)
                {
                    CDbFunction f(m_Logger, module.m_Functions[funcHash]);

                    f.m_Address = funcAddress;
                    f.m_Argc = argc;
                    f.m_Name = funcName;

                    if (f.m_IsEventEnabled && dbEvents && dbEvents->contains(funcHash))
                    {
                        f.m_EventHandler = dbEvents->at(funcHash);
                    }

                    module.m_DbFunctions.insert(std::pair<uint32_t, CDbFunction>(id, f));
                    continue;
                }
                else
                {
                    module.m_DbDisabledFuncId.insert(id);
                }
            }

            if (module.m_IsTraceAll && !module.m_DbDisabledFuncId.contains(id))
            {
                CDbFunction f(m_Logger, module);

                f.m_Address = funcAddress;
                f.m_Argc = argc;
                f.m_Name = funcName;

                if (f.m_IsEventEnabled && dbEvents && dbEvents->contains(funcHash))
                {
                    f.m_EventHandler = dbEvents->at(funcHash);
                }

                module.m_DbFunctions.insert(std::pair<uint32_t, CDbFunction>(id, f));
                continue;
            }
        }
    }
    return true;
}

bool CDataBase::IsSyscall(uint8_t* address, uint32_t& id, int8_t& argc)
{
    if (address[0] != 0xB8)
        return false;

    id = *(uint32_t*)&(address[1]);

    for (uint32_t i = 10; i < 32; i++)
    {
        switch (address[i])
        {
            case 0xc3:
                argc = 0;
                return true;

            case 0xc2:
                argc = ((uint16_t)address[i + 1]) / 4;
                return true;
        }
    }

    return false;
}