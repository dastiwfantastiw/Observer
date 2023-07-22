#pragma once
#include "config.h"
#include "events.h"
#include "logger.h"

#include <set>

class CDbFunction: public CFunction
{
private:
    CLogger& m_Logger;

public:
#pragma pack(push, 1)
    uint8_t* m_Address;
    std::string m_Name;
    uint16_t m_Argc;
    CEvent* m_EventHandler;
#pragma pack(pop)

    CDbFunction()
        : CFunction()
        , m_Logger(*new CLogger)
        , m_Address(0)
        , m_Argc(0)
        , m_EventHandler(NULL){};

    CDbFunction(CLogger& logger)
        : CFunction()
        , m_Logger(logger)
        , m_Address(0)
        , m_Argc(0)
        , m_EventHandler(NULL){};

    CDbFunction(CLogger& logger, CFunction& func)
        : CFunction(func)
        , m_Logger(logger)
        , m_Address(0)
        , m_Argc(0)
        , m_EventHandler(NULL){};

    CDbFunction(CLogger& logger, CModule& mod)
        : CFunction(mod)
        , m_Logger(logger)
        , m_Address(0)
        , m_Argc(0)
        , m_EventHandler(NULL){};

    ~CDbFunction(){};
};

typedef std::map<uint32_t, CDbFunction> DbFuncsContainer;
typedef std::map<uint32_t, CEvent*> DbEventsContainer;
class CDbModule: public CModule
{
private:
    CLogger& m_Logger;

public:
#pragma pack(push, 1)
    std::string m_Name;
    IMAGE_DOS_HEADER* m_ImageAddress;
    IMAGE_EXPORT_DIRECTORY* m_ImageExportAddress;
    uint32_t m_ImageExportSize;
#pragma pack(pop)

    DbFuncsContainer m_DbFunctions;
    std::set<uint32_t> m_DbDisabledFuncId;

    CDbModule()
        : CModule()
        , m_Logger(*new CLogger)
        , m_ImageAddress(NULL)
        , m_ImageExportAddress(NULL)
        , m_ImageExportSize(NULL){};

    CDbModule(CLogger& logger)
        : CModule()
        , m_Logger(logger)
        , m_ImageAddress(NULL)
        , m_ImageExportAddress(NULL)
        , m_ImageExportSize(NULL){};

    CDbModule(CLogger& logger, CModule& m)
        : CModule(m)
        , m_Logger(logger)
        , m_ImageAddress(NULL)
        , m_ImageExportAddress(NULL)
        , m_ImageExportSize(NULL){};

    ~CDbModule(){};
};

typedef std::map<uint32_t, CDbModule> CDbModuleContainer;
typedef std::map<uint32_t, CModule> CDbWaitModuleContainer;
typedef std::map<uint32_t, DbEventsContainer> DbModulesEventsContainer;
class CDataBase final
{
private:
    CLogger& m_Logger;
    DbModulesEventsContainer m_DbModulesEvents;
    CDbModuleContainer m_DbModules;

    CDbWaitModuleContainer m_DbWaitModules;

public:
    CDataBase(CLogger& logger)
        : m_Logger(logger)
    {
        m_DbModulesEvents[0x066b021f] =
            {
                std::make_pair(0x49ce0795, new OnCreateUserProcess(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x23500534, new OnOpenProcess(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x6c930948, new OnAllocateVirtualMemory(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0xaf070b59, new OnWow64AllocateVirtualMemory64(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x65f10904, new OnProtectVirtualMemory(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0xa6360b15, new OnWow64ProtectVirtualMemory64(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x49e4079f, new OnReadVirtualMemory(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x826a09b0, new OnWow64ReadVirtualMemory64(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x5450082e, new OnWriteVirtualMemory(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x8f9b0a3f, new OnWow64WriteVirtualMemory64(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x144703bf, new OnReadFile(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x19ac044e, new OnWriteFile(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x1d600497, new OnCreateFile(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x14c603d5, new OnOpenFile(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x586c082c, new OnDeviceIoControlFile(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x18dd0440, new OnCreateKey(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x18c7043f, new OnDeleteKey(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x33f1063c, new OnDeleteValueKey(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x22ea0515, new OnSetValueKey(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x2f7e05ff, new OnQueryValueKey(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x291b0592, new OnEnumerateKey(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x42680720, new OnGetContextThread(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x4328072c, new OnSetContextThread(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x33fb062c, new OnCreateThreadEx(m_Logger, PROCESS_MODE_POST_EXEC)),

                std::make_pair(0x2dfe05ec, new OnCreateSection(m_Logger, PROCESS_MODE_POST_EXEC)),
                std::make_pair(0x41080706, new OnMapViewOfSection(m_Logger, PROCESS_MODE_POST_EXEC)),
            };
    };

    ~CDataBase(){};

    bool Init(CConfig* config);

    bool IsFunctionExists(uint32_t id, CDbModule*& module, CDbFunction*& func);

    int CheckWaitList();

private:
    bool PEBFindModule(uint32_t hash, CDbModule& module);

    bool ModuleInitSyscalls(CDbModule& module, DbEventsContainer* dbEvents);

    bool IsSyscall(uint8_t* address, uint32_t& id, int8_t& argc);
};