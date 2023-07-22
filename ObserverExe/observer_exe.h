#pragma once
#include "config.h"
#include "inject.h"
#include <vector>

class CObserverExe
{
private:
    class CProcess
    {
    public:
        std::string m_ProcessImage, m_ProcessCommandLine;

        PROCESS_INFORMATION m_ProcInfo;

        CProcess()
        {
            m_ProcInfo = {};
        }

        ~CProcess()
        {
            CloseHandle(m_ProcInfo.hProcess);
            CloseHandle(m_ProcInfo.hThread);
        }

        bool RunProcess(const uint32_t flags)
        {
            STARTUPINFOA startUpInfo = {};

            startUpInfo.cb = sizeof(STARTUPINFOA);

            return CreateProcessA(
                m_ProcessImage.empty() ? NULL : m_ProcessImage.c_str(),
                m_ProcessCommandLine.empty() ? NULL : (char*)m_ProcessCommandLine.c_str(),
                NULL,
                NULL,
                false,
                flags,
                NULL,
                NULL,
                &startUpInfo,
                &m_ProcInfo);
        }

        bool KillProcess(uint32_t exitCode)
        {
            return TerminateProcess(m_ProcInfo.hProcess, exitCode);
        }
    } m_Process;

    CConfig m_Config;
    std::string m_ObserverDllPath;
    IMAGE_DOS_HEADER* m_ObserverImage;
    HANDLE m_MapDllHandle;

public:
    CObserverExe()
        : m_ObserverImage(NULL)
        , m_MapDllHandle(INVALID_HANDLE_VALUE){};

    ~CObserverExe()
    {
        CloseHandle(m_MapDllHandle);
    }

    void AddProcess(const char* imagePath)
    {
        m_Process.m_ProcessImage = imagePath;
        printf("[+] Image: %s\n", imagePath);
    }

    void AddProcessCommandLine(const char* commandLine)
    {
        m_Process.m_ProcessCommandLine = commandLine;
        printf("[+] CommandLine: %s\n", commandLine);
    }

    bool GetConfigFromJson(const char* path)
    {
        CConfig config;

        if (!config.LoadFromJson(path))
        {
            printf("[-] Failed to get JSON config %s\n", path);
            return false;
        }

        if (config.m_Magic != OBSERVER_CONFIG_MAGIC)
        {
            printf("[-] Incorrect MAGIC (0x%08x)\n", config.m_Magic);
            return false;
        }

        if (config.m_Version != OBSERVER_CONFIG_VERSION)
        {
            printf("[-] Incorrect VERSION (0x%04x)\n", config.m_Version);
            return false;
        }

        m_Config = config;

        printf("[+] JSON: %s\n", path);
        return false;
    }

    bool GetObserverDll(const char* path)
    {
        if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
        {
            printf("[-] GetFileAttributesA failed (0x%08x) [%s]\n", GetLastError(), path);
            return false;
        }

        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf("[-] CreateFileA failed (0x%08x) [%s]\n", GetLastError(), path);
            return false;
        }

        uint32_t fileSize = GetFileSize(hFile, NULL);

        if (fileSize < sizeof(IMAGE_DOS_HEADER))
        {
            printf("[-] Invalid file size [%s]\n", path);
            return false;
        }

        HANDLE hMapFile = CreateFileMappingA(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);
        if (hMapFile == INVALID_HANDLE_VALUE || hMapFile == NULL)
        {
            printf("[-] CreateFileMappingA failed (0x%08x) [%s]\n", GetLastError(), path);
            CloseHandle(hFile);
            return false;
        }

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)MapViewOfFile(hMapFile, FILE_MAP_READ, NULL, NULL, fileSize);
        if (!dosHeader)
        {
            printf("[-] MapViewOfFile failed (0x%08x) [%s]\n", GetLastError(), path);
            CloseHandle(hFile);
            CloseHandle(hMapFile);
            return false;
        }
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            printf("[-] Invalid IMAGE_DOS_SIGNATURE [%s]\n", path);
            CloseHandle(hFile);
            CloseHandle(hMapFile);
            return false;
        }

        if (((IMAGE_NT_HEADERS*)((uint8_t*)dosHeader + dosHeader->e_lfanew))->Signature != IMAGE_NT_SIGNATURE)
        {
            printf("[-] Invalid IMAGE_NT_SIGNATURE [%s]\n", path);
            CloseHandle(hFile);
            CloseHandle(hMapFile);
            return false;
        }

        m_MapDllHandle = hMapFile;
        m_ObserverDllPath = path;
        m_ObserverImage = dosHeader;

        CloseHandle(hFile);

        printf("[+] Dll: %s\n", path);
        return true;
    }

    bool Save(const char* path)
    {
        CBinaryConfig bin;
        m_Config.ToBinary(bin);
        if (bin.SaveToFile(path))
        {
            printf("[+] Save: %s\n", path);
            return true;
        }

        printf("[-] Cannot save binary config to file [%s]\n", path);
        return false;
    }

    bool Load(const char* path)
    {
        CBinaryConfig bin;
        if (bin.LoadFromFile(path))
        {
            CConfig config;

            if (!config.FromBinary(bin))
            {
                printf("[-] Unable to convert from binary config [%s]\n", path);
                return false;
            }

            if (config.m_Magic != OBSERVER_CONFIG_MAGIC)
            {
                printf("[-] Incorrect MAGIC (0x%08x)\n", config.m_Magic);
                return false;
            }

            if (config.m_Version != OBSERVER_CONFIG_VERSION)
            {
                printf("[-] Incorrect VERSION (0x%04x)\n", config.m_Version);
                return false;
            }

            m_Config = config;

            printf("[+] Load: %s\n", path);
            return true;
        }

        printf("[-] Cannot load binary config [%s]\n", path);
        return false;
    }

    void Help()
    {
        printf(
            "Usage: ./observer.exe [options]\n\n"
            "Options:\n"
            "--image\t\tPath to target process image\n"
            "--cmdline\tCommand line for the process\n"
            "--json\t\tPath to json config\n"
            "--dll\t\tPath to dll\n"
            "--save\t\tSave json config in binary format\n"
            "--load\t\tLoad binary config\n"
            "--execute\n");
    }

    bool Execute(char mode)
    {
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

        if (m_Process.m_ProcessCommandLine.empty() && m_Process.m_ProcessImage.empty())
        {
            printf("[-] No process for injection\n");
            return false;
        }

        if (!m_Process.RunProcess(NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP))
        {
            printf("[-] CreateProcessA failed (0x%08x) [%s:%s]\n", GetLastError(), m_Process.m_ProcessImage.c_str(), m_Process.m_ProcessImage.c_str());
            return false;
        }
        else
        {
            printf(
                "[+] Created process 0x%x (%d):\n"
                "\tImage: %s\n"
                "\tCommandLine: %s\n",
                m_Process.m_ProcInfo.dwProcessId,
                m_Process.m_ProcInfo.dwProcessId,
                m_Process.m_ProcessImage.c_str(),
                m_Process.m_ProcessCommandLine.c_str());
        }

        switch (mode)
        {
#ifdef _DEBUG

            case 'E':
            {
                if (m_ObserverDllPath.empty())
                {
                    printf("[-] No dll for injection\n");
                    return false;
                }

                CRemoteThreadInjection injector;

                if (!injector.Inject(m_Process.m_ProcInfo.hProcess, m_Process.m_ProcInfo.hThread, (char*)m_ObserverDllPath.c_str(), m_ObserverDllPath.length(), m_Config))
                {
                    m_Process.KillProcess(-1);
                    return false;
                }
                break;
            }
#endif // _DEBUG
            case 'e':
            {
                if (!m_ObserverImage || m_MapDllHandle == INVALID_HANDLE_VALUE)
                {
                    printf("[-] No dll for injection\n");
                    return false;
                }

                CReflectiveThreadInjection injector;

                m_Config.m_DllHandle = m_MapDllHandle;

                if (!injector.Inject(m_Process.m_ProcInfo.hProcess, m_Process.m_ProcInfo.hThread, m_ObserverImage, NULL, m_Config))
                {
                    m_Process.KillProcess(-1);
                    return false;
                }
                break;
            }
        }

        printf("[+] Executed\n");
        WaitForSingleObject(m_Process.m_ProcInfo.hProcess, INFINITE);
        return true;
    }
};