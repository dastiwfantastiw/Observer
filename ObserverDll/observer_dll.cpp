#include "observer_dll.h"
#include "args.h"

#include <psapi.h>
#include <tlhelp32.h>

#define OFFSET_ANTI_SELF_CATCHER 0x4
#define OFFSET_INPUT_JMP33 0x15
#define OFFSET_SC_HANDLER 0x23
#define OFFSET_JMP33 0x31

SyscallStatus __stdcall CObserverDll::SyscallHandler(uint32_t id, uint32_t* args, Registers* regs, void* jmpAddress)
{
    SyscallStatus status = NotExecuted;

    CObserverDll* observerDll = CObserverDll::GetInstance();

    if (observerDll)
    {
        observerDll->EnableThreadCatcher();

        SYSTEMTIME time;
        GetLocalTime(&time);

        CDbModule* dbModule = nullptr;
        CDbFunction* dbFunc = nullptr;

        if (observerDll->m_DataBase.IsFunctionExists(id, dbModule, dbFunc))
        {
            CArgs Args(observerDll->m_Logger, observerDll->m_Analyzer);

            if ((dbFunc->m_ProcMode & PROCESS_MODE_PRE_EXEC) && status == NotExecuted)
            {
                Args.AnalyzerArguments(args, dbFunc);
                Args.LogFunction(&time, dbModule, dbFunc, NULL);
            }

            if (dbFunc->m_IsEventEnabled && dbFunc->m_EventHandler && dbFunc->m_EventHandler->m_procMode & PROCESS_MODE_PRE_EXEC)
            {
                dbFunc->m_EventHandler->Callback(&time, id, args, regs, jmpAddress, dbModule, dbFunc, status);
            }

            observerDll->DisableThreadCatcher();
            observerDll->ExecuteSyscall(id, dbFunc->m_Argc, args, regs, jmpAddress);
            status = Executed;
            observerDll->EnableThreadCatcher();
            GetLocalTime(&time);

            if ((dbFunc->m_ProcMode & PROCESS_MODE_POST_EXEC) && status == Executed)
            {
                Args.AnalyzerArguments(args, dbFunc);
                Args.LogFunction(&time, dbModule, dbFunc, &regs->EAX);
            }

            if (dbFunc->m_IsEventEnabled && dbFunc->m_EventHandler && dbFunc->m_EventHandler->m_procMode & PROCESS_MODE_POST_EXEC)
            {
                dbFunc->m_EventHandler->Callback(&time, id, args, regs, jmpAddress, dbModule, dbFunc, status);
            }
        }

        observerDll->DisableThreadCatcher();
    }

    return status;
}

bool CObserverDll::EnableHook()
{
    uint8_t mainHookBytes[] =
        "\x60\x50\x50\xBA\x11\x11\x11\x11\xFF\xD2\x85\xC0\x58\x61\x75\x21\x55\x89"
        "\xE5\x60\x68\x22\x22\x22\x22\x8D\x55\xE0\x52\x8D\x55\x0C\x52\x50\xBA\x33"
        "\x33\x33\x33\xFF\xD2\x85\xC0\x61\x89\xEC\x5D\x75\x07\x90\x90\x90\x90\x90"
        "\x90\x90\xC3";

    uint8_t jmpToMainHookBytes[7] = "\x68\xDD\xCC\xBB\xAA\xC3";

    m_HookPage = (uint8_t*)VirtualAlloc(NULL, sizeof(mainHookBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m_HookPage)
        return false;

    memcpy(m_OriginalBytes, (const void*)__readfsdword(0xC0), sizeof(m_OriginalBytes));
    memcpy(m_HookPage, mainHookBytes, sizeof(mainHookBytes));

    *(void**)(m_HookPage + OFFSET_ANTI_SELF_CATCHER) = ThreadCatcher;
    *(void**)(m_HookPage + OFFSET_SC_HANDLER) = SyscallHandler;
    *(void**)(m_HookPage + OFFSET_INPUT_JMP33) = m_HookPage + OFFSET_JMP33;
    *(void**)(jmpToMainHookBytes + 1) = m_HookPage;
    memcpy(m_HookPage + OFFSET_JMP33, m_OriginalBytes, sizeof(m_OriginalBytes));

    MEMORY_BASIC_INFORMATION memoryInfo;

    if (!VirtualQuery((void*)__readfsdword(0xC0), &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        VirtualFree(m_HookPage, NULL, MEM_RELEASE);
        return false;
    }

    if (memoryInfo.AllocationProtect != PAGE_EXECUTE_READWRITE)
    {
        if (!VirtualProtect(memoryInfo.BaseAddress, memoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &memoryInfo.Protect))
        {
            VirtualFree(m_HookPage, NULL, MEM_RELEASE);
            return false;
        }
    }

    return !(memcpy((void*)__readfsdword(0xC0), jmpToMainHookBytes, sizeof(jmpToMainHookBytes)));
}

bool CObserverDll::DisableHook()
{
    if (m_HookPage)
    {
        memcpy((void*)__readfsdword(0xC0), m_OriginalBytes, sizeof(m_OriginalBytes));
        return VirtualFree(m_HookPage, 0, MEM_RELEASE);
    }

    return TlsFree(m_TlsCatch);
}

bool CObserverDll::EnableThreadCatcher()
{
    return TlsSetValue(m_TlsCatch, (uint32_t*)GetCurrentThreadId());
}

bool CObserverDll::DisableThreadCatcher()
{
    return TlsSetValue(m_TlsCatch, (uint32_t*)-1);
}

bool CObserverDll::Init(InjectData* data)
{
    if (((uint32_t)0xfffff000 & (uint32_t)data) > 0)
    {
        if (data->BinaryConfig && data->BinaryConfigSize)
        {
            CBinaryConfig bin(data->BinaryConfig, data->BinaryConfigSize);
            if (!m_Config.FromBinary(bin))
                return false;
        }
    }
#ifdef _DEBUG
    else
    {
        CBinaryConfig bin;
        if (!bin.LoadFromFile("C:\\Users\\Alexander\\Desktop\\json.bin"))
            return false;

        if (!m_Config.FromBinary(bin))
            return false;
    }
#endif

    if (!m_Logger.CreateLogFile(m_Config.m_LogPath.c_str()))
        return false;

    LogProcessInfo();

    return m_DataBase.Init(&m_Config);
}

bool CObserverDll::Migrate(HANDLE hProcess, HANDLE hThread)
{
    if (m_Config.m_DllHandle == INVALID_HANDLE_VALUE)
    {
        m_Logger.Trace("; Migration is not possible (DllHandle=0x%08x)\n", m_Config.m_DllHandle);
        return false;
    }

    return m_Migrate.Migrate(hProcess, hThread, m_Config);
}

NTSTATUS __stdcall CObserverDll::ExecuteSyscall(uint32_t id, uint16_t argc, uint32_t* args, Registers* regs, void* jmpAddress)
{
    uint32_t* ptrArgument = args + argc - 1;
    for (uint32_t i = 0; i < argc; i++)
    {
        uint32_t argument = *ptrArgument;
        _asm push argument;
        ptrArgument--;
    }
    uint32_t retArgc = argc * 4;

    _asm
    {
        call $+5
        mov eax, id
        mov edx, jmpAddress
        call edx
        add esp, retArgc
        push edx
        mov edx, regs
        mov[edx].EAX, eax
        pop edx
    }
    return (NTSTATUS)regs->EAX;
}

CatchStatus __stdcall CObserverDll::ThreadCatcher(uint32_t id)
{
    CatchStatus status = DontSkip;
    if ((uint32_t)TlsGetValue(CObserverDll::GetInstance()->m_TlsCatch) == (uint32_t)GetCurrentThreadId())
    {
        status = Skip;
    }
    return status;
}

void CObserverDll::LogProcessInfo()
{
    uint32_t pid = GetCurrentProcessId();
    m_Logger.Trace("Process ID: 0x%x (%d)\n", pid, pid);

    char image[MAX_PATH + 1];

    GetModuleFileNameA(NULL, image, sizeof(image));

    if (GetLastError() == ERROR_SUCCESS)
    {
        m_Logger.Trace("Process ImagePath: %s\n", image);
    }

    m_Logger.Trace("Process CommandLine: %s\n", GetCommandLineA());

    std::string md5hash;

    if (GetFileMD5Hash(image, md5hash))
    {
        m_Logger.Trace("File MD5 hash: %s\n", md5hash.c_str());
    }

    uint32_t ppid = GetParentProcessId();

    m_Logger.Trace("\n");

    if (ppid)
    {
        m_Logger.Trace("Parent Process ID: 0x%x (%d)\n", ppid, ppid);

        HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, ppid);
        if (hParentProcess != INVALID_HANDLE_VALUE)
        {
            if (K32GetModuleFileNameExA(hParentProcess, NULL, image, sizeof(image)))
            {
                m_Logger.Trace("Parent Process ImagePath: %s\n", image);
            }
        }
    }

    m_Logger.Trace("\n");
}

bool CObserverDll::GetFileMD5Hash(const char* filePath, std::string& output)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    DWORD cbHash = 16;

    std::vector<uint8_t> rgbHash;
    rgbHash.resize(cbHash);

    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (CryptAcquireContextA(&hProv,
                             NULL,
                             NULL,
                             PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))
    {
        if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return false;
        }

        const uint32_t size = 4 * 1024;
        uint8_t buffer[size] = {};

        DWORD readed = 0;

        while (ReadFile(hFile, buffer, size, &readed, NULL))
        {
            if (!readed)
                break;

            if (!CryptHashData(hHash, buffer, readed, 0))
            {
                CryptReleaseContext(hProv, 0);
                CryptDestroyHash(hHash);
                CloseHandle(hFile);
                return false;
            }
        }

        CloseHandle(hFile);

        if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash.data(), &cbHash, 0))
        {
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            HexBytesToString(rgbHash.data(), cbHash, output);
            return true;
        }
    }
    return false;
}

void CObserverDll::HexBytesToString(uint8_t* data, uint32_t size, std::string& output)
{
    const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    output.resize(size * 2);
    for (uint32_t i = 0; i < size; ++i)
    {
        output[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
        output[2 * i + 1] = hexmap[data[i] & 0x0F];
    }
}

uint32_t CObserverDll::GetParentProcessId()
{
    PROCESSENTRY32 processEntry = {};

    HANDLE hSnapShot = INVALID_HANDLE_VALUE;

    uint32_t pid = GetCurrentProcessId();
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hSnapShot, &processEntry))
    {
        do
        {
            if (processEntry.th32ProcessID == pid)
            {
                CloseHandle(hSnapShot);
                return processEntry.th32ParentProcessID;
            }
        } while (Process32Next(hSnapShot, &processEntry));
    }

    CloseHandle(hSnapShot);
    return 0;
}
