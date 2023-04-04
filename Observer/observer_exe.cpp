#include "observer_exe.h"

#include <algorithm>
#include <iterator>
#include <set>

#include "hash.h"
#include "inject.h"

using namespace config;

namespace observer_exe {

void ObserverExe::GetProcessImagePath(const char* imagePath)
{
    ProcessImagePath = imagePath;
    printf("[+] Got process image: %s (%d bytes)\n", ProcessImagePath.c_str(), ProcessImagePath.length());
}

void ObserverExe::GetProcessCommandLine(const char* cmdline)
{
    ProcessCmdLine = cmdline;
    printf("[+] Got process command line: %s (%d bytes)\n",
           ProcessCmdLine.c_str(),
           ProcessCmdLine.length());
}

bool ObserverExe::GetDll(const char* dllPath)
{
    printf("[%%] Getting Dll: %s", dllPath);

    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
    {
        printf("\n\t[-] Error: CreateFileA failed (0x%08x)\n", GetLastError());
        return false;
    }

    uint32_t fileSize = GetFileSize(hFile, NULL);

    HANDLE hMappingFile =
        CreateFileMappingA(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);

    if (hMappingFile == INVALID_HANDLE_VALUE || hMappingFile == NULL)
    {
        printf("\n\t[-] Error: CreateFileMappingA failed (0x%08x)\n",
               GetLastError());
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    DllInfo.MapView = (IMAGE_DOS_HEADER*)MapViewOfFile(
        hMappingFile,
        FILE_MAP_READ,
        NULL,
        NULL,
        fileSize);

    if (!DllInfo.MapView)
    {
        printf("\n\t[-] Error: MapViewOfFile failed (0x%08x)\n", GetLastError());
        CloseHandle(hMappingFile);
        return false;
    }

    DllInfo.MapHandle = hMappingFile;
    DllInfo.Path = dllPath;

    printf("\r[+] Got dll: %s, MapHandle: 0x%08x\n",
           DllInfo.Path.c_str(),
           DllInfo.MapHandle);

    return true;
}

bool ObserverExe::GetJson(const char* jsonPath)
{
    printf("[%%] Getting json: %s", jsonPath);

    HANDLE hFile = CreateFileA(jsonPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
    {
        printf("\n\t[-] Error: CreateFileA failed (0x%08x)\n", GetLastError());
        return false;
    }

    uint32_t size = GetFileSize(hFile, NULL);

    char* json = (char*)calloc(size, 1);
    if (!json)
    {
        printf("\n\t[-] Error: calloc failed (0x%08x)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    if (!ReadFile(hFile, json, size, NULL, NULL))
    {
        printf("\n\t[-] Error: ReadFile failed (0x%08x)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    auto js = json::parse(json, nullptr, false);
    if (js.is_discarded())
    {
        printf("\n\t[-] Error: Invalid json\n");
        return false;
    }

    Config = JsonToBinary(js);

    if (Config)
    {
        printf("\r[+] Got binary from json: %s\n", jsonPath);
        return true;
    }
    printf("\n\t[-] Error: Unable to convert json into binary format\n");
    return false;
}

bool ObserverExe::Execute(bool isDebug)
{
    if (isDebug == false && Config == NULL)
    {
        return false;
    }

    printf("[%%] Injecting");
    HANDLE hToken = INVALID_HANDLE_VALUE;
    LUID luid = {};
    TOKEN_PRIVILEGES tokenPriv = {};

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid))
        {
            tokenPriv.PrivilegeCount = 1;
            tokenPriv.Privileges[0].Luid = luid;
            tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
        }
    }

    if (ProcessImagePath.empty() && ProcessCmdLine.empty())
    {
        printf("\n\t[-] Error: Process image path and command line are empty\n");
        return false;
    }

    STARTUPINFOA startInfo = {0};
    PROCESS_INFORMATION processInfo = {0};

    startInfo.cb = sizeof(STARTUPINFOA);

    if (!CreateProcessA(
            ProcessImagePath.empty() ? NULL : ProcessImagePath.c_str(),
            ProcessCmdLine.empty() ? NULL : (char*)ProcessCmdLine.c_str(),
            NULL,
            NULL,
            false,
            NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED | CREATE_NEW_CONSOLE |
                CREATE_NEW_PROCESS_GROUP,
            NULL,
            NULL,
            &startInfo,
            &processInfo))
    {
        printf("\n\t[-] Error: CreateProcessA failed (0x%08x)\n", GetLastError());
        return false;
    }

    uint16_t processMachine = 0;
    uint16_t nativeMachine = 0;

    if (IsWow64Process2(processInfo.hProcess, &processMachine, &nativeMachine) &&
        IMAGE_FILE_MACHINE_UNKNOWN == processMachine)
    {
        printf("\n\t[-] Error: The created process is 64-bit\n");
        TerminateProcess(processInfo.hProcess, -1);
        return false;
    }

    HANDLE diplicatedHandle = INVALID_HANDLE_VALUE;

    if (!DuplicateHandle(GetCurrentProcess(), DllInfo.MapHandle, processInfo.hProcess, &diplicatedHandle, NULL, false, DUPLICATE_SAME_ACCESS))
    {
        printf("\n\t[-] Error: DuplicateHandle failed (0x%08x)\n", GetLastError());
        TerminateProcess(processInfo.hProcess, -1);
        return false;
    }

    if (isDebug ? inject::LoadLibraryInject(processInfo.hProcess, DllInfo.Path)
                : inject::ReflectiveThreadHijackingInject(
                      processInfo.hProcess,
                      processInfo.hThread,
                      diplicatedHandle,
                      DllInfo.MapView,
                      Config))
    {
        printf(
            "\r[+] Injected into Pid: 0x%x (%d), Tid: 0x%x (%d)\n",
            processInfo.dwProcessId,
            processInfo.dwProcessId,
            processInfo.dwThreadId,
            processInfo.dwThreadId);
        ResumeThread(processInfo.hThread);
        return true;
    }

    printf("\n\t[-] Error: Injection failed (0x%08x)\n", GetLastError());
    TerminateProcess(processInfo.hProcess, -1);
    return false;
}

bool ObserverExe::SaveBinaryToFile(const char* filePath)
{
    printf("[%%] Saving binary: %s", filePath);
    if (!Config)
    {
        printf("\n\t[-] Error: There is no binary config\n");
        return false;
    }

    uint32_t size = Config->Header.Size;

    HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
    {
        printf("\n\t[-] Error: CreateFileA failed (0x%08x)\n", GetLastError());
        return false;
    }

    if (!WriteFile(hFile, Config, size, NULL, NULL))
    {
        printf("\n\t[-] Error: WriteFile failed (0x%08x)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    printf("\r[+] Saved binary: %s (%d bytes)\n", filePath, size);
    CloseHandle(hFile);
    return true;
}

bool ObserverExe::ReadBinaryFromFile(const char* filePath)
{
    printf("[%%] Reading binary: %s", filePath);
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
    {
        printf("\n\t[-] Error: CreateFileA failed (0x%08x)\n", GetLastError());
        return false;
    }

    uint32_t size = GetFileSize(hFile, NULL);

    BinaryConfig* config = (BinaryConfig*)calloc(size, 1);
    if (!config)
    {
        printf("\n\t[-] Error: calloc failed (0x%08x)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    if (!ReadFile(hFile, config, size, NULL, NULL))
    {
        printf("\n\t[-] Error: ReadFile failed (0x%08x)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    printf("\r[+] Read binary: %s (%d bytes)\n", filePath, size);
    CloseHandle(hFile);

    printf("[Header]:\n\tMagic: 0x%08x\n\tSize: %d bytes\n", config->Header.Magic, config->Header.Size);
    printf("[Dll]:\n\tMapHandle: 0x%08p\n", config->MapHandle);
    printf("[LogPath]:\n\t%s (%d bytes)\n", &config->LogPath[0], lstrlenA(&config->LogPath[0]));

    if (config->ModulesCount > 0)
    {
        config::ModuleData* ptrModule = config->Modules;

        uint32_t k = 0;
        while (k < config->ModulesCount)
        {
            config::FunctionData* ptrFuncData = (FunctionData*)(ptrModule + 1);
            printf(
                "[%d] ModuleHash: 0x%08x, Enabled: %s, Events: %s, Mode: 0x%02x, Types: 0x%04x, "
                "MaxPtr: %d, "
                "MinStrLen: %d, "
                "MaxStrLen: %d, "
                "FuncCount: %d\n",
                k + 1,
                ptrModule->ModuleHash,
                ptrModule->EnabledAll ? "true" : "false",
                ptrModule->EventsEnabledAll ? "true" : "false",
                ptrModule->ModeAll,
                ptrModule->TypeAll,
                ptrModule->MaxPtrAll,
                ptrModule->MinStrLenAll,
                ptrModule->MaxStrLenAll,
                ptrModule->FuncCount);

            for (uint32_t f = 0; f < ptrModule->FuncCount; f++)
            {
                printf(
                    "\t[%d] FuncHash: 0x%08x, Enabled: %s, Events: %s, Mode: 0x%02x, Types: "
                    "0x%04x, MaxPtr: %d, MinStrLen: %d, MaxStrLen: %d\n",
                    f + 1,
                    ptrFuncData->FuncHash,
                    ptrFuncData->Enabled ? "true" : "false",
                    ptrFuncData->EventsEnabled ? "true" : "false",
                    ptrFuncData->Mode,
                    ptrFuncData->Types,
                    ptrFuncData->MaxPtr,
                    ptrFuncData->MinStrLen,
                    ptrFuncData->MaxStrLen);
                ptrFuncData++;
            }
            ptrModule = (ModuleData*)(ptrFuncData);
            k++;
        }
    }

    return true;
}

ObserverExe::ObserverExe()
{
    ProcessImagePath.clear();
    ProcessCmdLine.clear();

    DllInfo.Path.clear();
    DllInfo.MapView = NULL;
    DllInfo.MapHandle = INVALID_HANDLE_VALUE;
    Config = NULL;
}

config::BinaryConfig* ObserverExe::JsonToBinary(json& js)
{
    std::vector<uint8_t> lConfig;
    lConfig.resize(sizeof(BinaryConfig) - sizeof(config::ModuleData));

    ((BinaryConfig*)lConfig.data())->Header.Magic = MAGIC;
    ((BinaryConfig*)lConfig.data())->Header.Size = sizeof(config::BinaryConfig);
    ((BinaryConfig*)lConfig.data())->MapHandle = INVALID_HANDLE_VALUE;
    ((BinaryConfig*)lConfig.data())->ModulesCount = 0;

    std::memset(&((BinaryConfig*)lConfig.data())->LogPath, 0, MAX_PATH);

    json::object_t jsObserver, jsSyscalls;

    std::filesystem::path logPath;

    if (!GetFromJson<json, json::object_t&>("observer", "object", js, jsObserver))
    {
        printf("\n\tError: Incorrect json's struct");
        return NULL;
    }

    GetFromJson<json::object_t, std::filesystem::path&>("log", "string", jsObserver, logPath);

    if (!logPath.empty())
    {
        std::u8string log = logPath.u8string();
        if ((log.length() > 0) && (log.length() < MAX_PATH))
        {
            std::memcpy(&((BinaryConfig*)lConfig.data())->LogPath[0], log.c_str(), log.length());
        }
        else
        {
            printf("\n\tError: Incorrect LogPath size");
            return NULL;
        }
    }

    GetFromJson<json::object_t, json::object_t&>("syscalls", "object", jsObserver, jsSyscalls);

    for (auto iterModule = jsSyscalls.begin();
         iterModule != jsSyscalls.end();
         iterModule++)
    {
        std::vector<uint8_t> md, fd;

        json::object_t jsFunctions;

        if (GetModuleInfo(iterModule->first, iterModule->second, md))
        {
            GetFromJson<json, json::object_t&>("functions", "object", iterModule->second, jsFunctions);

            if (!jsFunctions.empty())
            {
                GetFuncsInfo(jsFunctions, *((ModuleData*)md.data()), fd);
            }

            if (((ModuleData*)md.data())->EnabledAll == false && fd.empty())
            {
                continue;
            }

            ((ModuleData*)md.data())->FuncCount = fd.size() / sizeof(FunctionData);

            lConfig += md + fd;
            ((BinaryConfig*)lConfig.data())->ModulesCount++;
        }
    }

    ((BinaryConfig*)lConfig.data())->Header.Size = lConfig.size();

    BinaryConfig* config = (BinaryConfig*)calloc(lConfig.size(), 1);
    if (config)
    {
        std::memcpy(config, lConfig.data(), lConfig.size());
        return config;
    }

    return NULL;
}

bool ObserverExe::GetModuleInfo(const std::string& moduleName, json& js, std::vector<uint8_t>& vecMd)
{
    static std::set<uint32_t> uniqHashes;

    std::filesystem::path modulePath(moduleName);
    std::string moduleFileName = modulePath.stem().string();
    std::transform(moduleFileName.begin(), moduleFileName.end(), moduleFileName.begin(), ::tolower);

    uint32_t hash = adler32((const unsigned char*)moduleFileName.c_str(),
                            moduleFileName.length());

    if (uniqHashes.contains(hash))
    {
        return false;
    }

    config::ModuleData tmpMd = {
        hash,              //ModuleHash
        false,             //EnabledAll
        false,             //EventsEnabled
        Mode::ModeUnknown, //ModeAll
        Type::TypeUnknown, //TypeAll
        0,                 //MaxPtrAll
        1,                 //MinStrLenAll
        128,               //MaxStrLenAll
        0};                //FuncCount

    GetFromJson<json, bool&>("enabled", "boolean", js, tmpMd.EnabledAll);
    GetFromJson<json, bool&>("events", "boolean", js, tmpMd.EventsEnabledAll);

    std::string strMode;
    if (GetFromJson<json, std::string&>("mode", "string", js, strMode))
    {
        StringModeToBin(strMode, tmpMd.ModeAll);
    }

    json::array_t types;
    if (GetFromJson<json, json::array_t&>("types", "array", js, types))
    {
        StringTypeToBin(types, tmpMd.TypeAll);
    }

    GetFromJson<json, uint8_t&>("maxPtr", "number", js, tmpMd.MaxPtrAll);

    GetFromJson<json, uint32_t&>("minStrLen", "number", js, tmpMd.MinStrLenAll);
    GetFromJson<json, uint32_t&>("maxStrLen", "number", js, tmpMd.MaxStrLenAll);

    uint8_t* ptr = (uint8_t*)&tmpMd;

    vecMd.insert(vecMd.end(), ptr, ptr + sizeof(tmpMd));
    uniqHashes.insert(hash);

    return true;
}

bool ObserverExe::GetFuncsInfo(json::object_t& js, config::ModuleData& md, std::vector<uint8_t>& vecFd)
{
    static std::set<uint32_t> uniqHashes;

    for (auto iterFunc = js.begin(); iterFunc != js.end(); iterFunc++)
    {
        uint32_t hash = adler32((const unsigned char*)iterFunc->first.c_str(),
                                iterFunc->first.length());

        if (uniqHashes.contains(hash))
        {
            continue;
        }

        FunctionData tmpFd = {
            hash,                //FuncHash
            md.EnabledAll,       //Enabled
            md.EventsEnabledAll, //EventsEnabledAll
            md.ModeAll,          //Mode
            md.TypeAll,          //Types
            md.MaxPtrAll,        //MaxPtr
            md.MinStrLenAll,     //MinStrLen
            md.MaxStrLenAll};    //MaxStrLen

        GetFromJson<json, bool&>("enabled", "boolean", iterFunc->second, tmpFd.Enabled);
        GetFromJson<json, bool&>("events", "boolean", iterFunc->second, tmpFd.EventsEnabled);

        std::string strMode;
        if (GetFromJson<json, std::string&>("mode", "string", iterFunc->second, strMode))
        {
            StringModeToBin(strMode, tmpFd.Mode);
        }

        json::array_t types;
        if (GetFromJson<json, json::array_t&>("types", "array", iterFunc->second, types))
        {
            StringTypeToBin(types, tmpFd.Types);
        }

        GetFromJson<json, uint8_t&>("maxPtr", "number", iterFunc->second, tmpFd.MaxPtr);

        GetFromJson<json, uint32_t&>("minStrLen", "number", iterFunc->second, tmpFd.MinStrLen);
        GetFromJson<json, uint32_t&>("maxStrLen", "number", iterFunc->second, tmpFd.MaxStrLen);

        uint8_t* ptr = (uint8_t*)&tmpFd;

        vecFd.insert(vecFd.end(), ptr, ptr + sizeof(tmpFd));
    }

    return true;
}

void ObserverExe::StringModeToBin(std::string& str, config::Mode& dest)
{
    if (str.empty())
    {
        dest = Mode::ModeUnknown;
        return;
    }

    if (ConfigModes.contains(str))
    {
        dest = ConfigModes[str];
    }
}

void ObserverExe::StringTypeToBin(json::array_t& js, config::Type& dest)
{
    if (js.empty())
    {
        dest = Type::TypeUnknown;
        return;
    }

    for (auto it = js.begin(); it != js.end(); it++)
    {
        if (!it->is_string())
        {
            printf("\n\tError: Type should be a string");
            return;
        }

        std::string strType = it->get<std::string>();

        if (ConfigTypes.contains(strType))
        {
            dest |= ConfigTypes[strType];
        }
    }
}
} // namespace observer_exe