#pragma once
#include "analyzer.h"
#include "database.h"
#include "migrate.h"

enum CatchStatus : uint32_t
{
    DontSkip,
    Skip
};

typedef SyscallStatus(WINAPI* SyscallsHandler)(uint32_t id, uint32_t* args, Registers* regs, void* jmpAddress);
typedef CatchStatus(WINAPI* ThreadCatchHandler)(uint32_t id);

class CObserverDll final
{
public:
    static CObserverDll* GetInstance()
    {
        static CObserverDll* instance;

        if (instance == nullptr)
        {
            instance = new CObserverDll;
        }
        return instance;
    }

    bool EnableHook();
    bool DisableHook();

    bool EnableThreadCatcher();
    bool DisableThreadCatcher();

    bool Init(InjectData* data);

    void Destroy()
    {
        delete this;
    }

    int CheckWaitList()
    {
        return m_DataBase.CheckWaitList();
    }

    bool Migrate(HANDLE hProcess, HANDLE hThread);

private:
    CLogger m_Logger;

    CMigrate m_Migrate;
    CAnalyzer m_Analyzer;
    CDataBase m_DataBase;
    CConfig m_Config;

    uint8_t* m_HookPage;
    uint8_t m_OriginalBytes[7]{};
    uint32_t m_TlsCatch;

    CObserverDll()
        : m_Logger()
        , m_Migrate(m_Logger)
        , m_Analyzer(m_Logger)
        , m_DataBase(m_Logger)
        , m_HookPage(NULL)
        , m_TlsCatch(TlsAlloc()){};

    ~CObserverDll()
    {
        DisableHook();
    };

    CObserverDll(const CObserverDll&) = delete;
    CObserverDll(CObserverDll&) = delete;
    CObserverDll& operator=(CObserverDll const&) = delete;

    static SyscallStatus __stdcall SyscallHandler(uint32_t id, uint32_t* args, Registers* regs, void* jmpAddress);
    static NTSTATUS __stdcall ExecuteSyscall(uint32_t id, uint16_t argc, uint32_t* args, Registers* regs, void* jmpAddress);
    static CatchStatus __stdcall ThreadCatcher(uint32_t id);

    void LogProcessInfo();

    bool GetFileMD5Hash(const char* filePath, std::string& output);
    void HexBytesToString(uint8_t* data, uint32_t size, std::string& output);

    uint32_t GetParentProcessId();
};