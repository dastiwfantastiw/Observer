#include "observer_dll.h"
#include "analyzer.h"
#include "db.h"

#define OFFSET_ANTI_SELF_CATCHER 0x4
#define OFFSET_INPUT_JMP33 0x15
#define OFFSET_SC_HANDLER 0x23
#define OFFSET_JMP33 0x31

namespace observer_dll {

uint8_t OriginalBytes[7];
uint32_t Guard = TlsAlloc();
inject::ObserverDllData* InjectData;
DbFuncs* DbFunctions = new DbFuncs;

} // namespace observer_dll

bool observer_dll::InstallHook()
{
    uint8_t hookBytes[] =
        "\x60\x50\x50\xBA\x11\x11\x11\x11\xFF\xD2\x85\xC0\x58\x61\x75\x21\x55\x89"
        "\xE5\x60\x68\x22\x22\x22\x22\x8D\x55\xE0\x52\x8D\x55\x0C\x52\x50\xBA\x33"
        "\x33\x33\x33\xFF\xD2\x85\xC0\x61\x89\xEC\x5D\x75\x07\x90\x90\x90\x90\x90"
        "\x90\x90\xC3";
    uint8_t preHookBytes[7] = "\x68\xDD\xCC\xBB\xAA\xC3";

    uint8_t* hookPage = (uint8_t*)VirtualAlloc(
        NULL,
        sizeof(hookBytes),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (hookPage)
    {
        std::memcpy(OriginalBytes, (const void*)__readfsdword(0xc0), sizeof(OriginalBytes));
        std::memcpy(hookPage, hookBytes, sizeof(hookBytes));

        *(void**)(hookPage + OFFSET_ANTI_SELF_CATCHER) = ThreadGuard;
        *(void**)(hookPage + OFFSET_SC_HANDLER) = SyscallHandler;
        *(void**)(hookPage + OFFSET_INPUT_JMP33) = hookPage + OFFSET_JMP33;
        *(void**)(preHookBytes + 1) = hookPage;
        std::memcpy(hookPage + OFFSET_JMP33, OriginalBytes, sizeof(OriginalBytes));

        MEMORY_BASIC_INFORMATION memInfo = {0};

        if (!VirtualQuery((void*)__readfsdword(0xc0), &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
        {
            VirtualFree(hookPage, NULL, MEM_RELEASE);
            return false;
        }

        if (memInfo.AllocationProtect != PAGE_EXECUTE_READWRITE)
        {
            if (!VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, PAGE_EXECUTE_READWRITE, &memInfo.Protect))
            {
                VirtualFree(hookPage, NULL, MEM_RELEASE);
                return false;
            }
        }

        std::memcpy((void*)__readfsdword(0xc0), preHookBytes, sizeof(preHookBytes));
        return true;
    }
    return false;
}

void observer_dll::UninstallHook()
{
    std::memcpy((void*)__readfsdword(0xc0), OriginalBytes, sizeof(OriginalBytes));
}

bool observer_dll::InitFromConfig(HMODULE hModule, inject::ObserverDllData* injectData)
{
    if (memory::IsBadReadAddress(injectData, 0))
    {
        char buffer[1024];
        if (GetEnvironmentVariableA("ObserverDllDebugConfig", (char*)&buffer, sizeof(buffer)))
        {
            HANDLE hFile = CreateFileA(buffer,
                                       GENERIC_READ,
                                       FILE_SHARE_READ,
                                       NULL,
                                       OPEN_EXISTING,
                                       NULL,
                                       NULL);
            if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
            {
                return false;
            }

            uint32_t size = GetFileSize(hFile, NULL);

            injectData = (inject::ObserverDllData*)VirtualAlloc(NULL, sizeof(injectData) + size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!injectData)
            {
                CloseHandle(hFile);
                return false;
            }

            if (!ReadFile(hFile, injectData + 1, size, NULL, NULL))
            {
                CloseHandle(hFile);
                VirtualFree(injectData, NULL, MEM_RELEASE);
                return false;
            }

            CloseHandle(hFile);
            injectData->BinConfig = (config::BinaryConfig*)(injectData + 1);
        }
        else
        {
            MessageBoxA(0, "Unable to get environment variable fro debug config", "ObserverDll", MB_ICONERROR);
        }
    }

    std::filesystem::path logPath = injectData->BinConfig->LogPath;

    if (!logger::CreateLogFile((char*)logPath.parent_path().u8string().empty() ? NULL : (char*)logPath.parent_path().u8string().c_str(),
                               (char*)logPath.filename().u8string().c_str() ? NULL : (char*)logPath.filename().u8string().c_str()))
    {
        if (!logger::CreateLogFile(NULL, NULL))
        {
            MessageBoxA(0, "Failed to create log file", "ObserverDll", MB_ICONERROR);
            return false;
        }
    }

    LogProcessInformation();

    if (injectData->BinConfig->ModulesCount > 0)
    {
        config::ModuleData* ptrModule = injectData->BinConfig->Modules;

        uint32_t k = 0;
        while (k < injectData->BinConfig->ModulesCount)
        {
            config::FunctionData* ptrFuncData =
                (config::FunctionData*)(ptrModule + 1);
            IMAGE_DOS_HEADER* imageModule = db::FindModule(ptrModule->ModuleHash);
            if (imageModule)
            {
                std::map<uint32_t, config::FunctionData> mapFuncs;
                for (uint32_t f = 0; f < ptrModule->FuncCount; f++)
                {
                    mapFuncs.insert(std::pair<uint32_t, config::FunctionData>(
                        ptrFuncData->FuncHash,
                        *ptrFuncData));
                    ptrFuncData++;
                }
                db::GetSyscallFromModule(imageModule, *DbFunctions, *ptrModule, mapFuncs);
            }

            ptrModule = (config::ModuleData*)(ptrFuncData);
            k++;
        }
    }

    InjectData = injectData;
    return true;
}

bool WINAPI observer_dll::ExecuteSystemCall(uint32_t id, uint16_t argc, uint32_t* args, Registers* regs, void* jump)
{
    uint32_t* ptrArgument = args + argc - 1;
    for (uint32_t i = 0; i < argc; i++)
    {
        uint32_t argument = *ptrArgument;
        _asm {
        push argument
        }
        ptrArgument--;
    }
    uint32_t retArgc = argc * 4;

    _asm {
    call $+5
    mov eax, id
	mov edx, jump
	call edx
	add esp, retArgc
	mov edx, regs
	mov[edx].EAX, eax
    }
    return regs->EAX;
}

bool observer_dll::Migrate(HANDLE processHandle, HANDLE threadHandle)
{
    return observer_dll::InjectData->Loader ? migrate::Migrate(processHandle, threadHandle, observer_dll::InjectData) : migrate::MigrateDebug(processHandle, threadHandle);
}

bool observer_dll::EnableGuardForThread()
{
    return TlsSetValue(observer_dll::Guard, (uint32_t*)GetCurrentThreadId());
}

bool observer_dll::DisableGuardForThread()
{
    return TlsSetValue(observer_dll::Guard, (uint32_t*)-1);
}

void observer_dll::LogProcessInformation()
{
    uint32_t pid = GetProcessId(GetCurrentProcess());
    char imageBuffer[MAX_PATH];
    std::string fileMD5, fileSHA256;

    std::vector<std::string> info;

    info.push_back(std::format("PID: {:#x} ({:d})\n", pid, pid));

    uint32_t len = GetModuleFileNameA(NULL, imageBuffer, MAX_PATH);
    if (!len)
    {
        logger::Trace("; Error: GetModuleFileNameA failed with code 0x%08x\n", GetLastError());
    }
    else
    {
        info.push_back(std::format("ImagePath: {:s}\n", imageBuffer));
    }

    info.push_back(std::format("CommandLine: {:s}\n", GetCommandLineA()));

    if (!analyzer::CalculateMD5Hash(imageBuffer, fileMD5))
    {
        logger::Trace("; Error: CalculateMD5Hash failed with code 0x%08x\n", GetLastError());
    }

    info.push_back(std::format("File MD5: {:s}\n", fileMD5.c_str()));
    info.push_back("\n");

    for (auto it = info.begin(); it != info.end(); it++)
    {
        logger::Trace(it->c_str());
    }
}
