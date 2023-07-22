#pragma once
#include <Windows.h>
#include <filesystem>
#include <format>
#include <string>

namespace fs = std::filesystem;

class CLogger final
{
private:
    CRITICAL_SECTION crit;

    HANDLE m_hLog;
    std::string m_defaultDir;
    std::string m_defaultName;

    bool WriteLog(const void* data, const size_t size);

public:
    bool CreateLogFile(const char* path);

    template<typename... Args>
    bool LogFormat(const char* format, Args... args)
    {
        std::string result = std::vformat(format, std::make_format_args(std::forward<Args>(args)...));

        return WriteLog(result.data(), result.size());
    }

    template<typename... Args>
    bool Trace(const char* format, Args... args)
    {
        int length = std::snprintf(NULL, 0, format, args...);
        if (length)
        {
            char* buf = new char[length + 1];
            std::snprintf(buf, length + 1, format, args...);

            bool result = WriteLog(buf, length);
            delete[] buf;
            return result;
        }
        return false;
    }

    CLogger()
        : m_hLog(INVALID_HANDLE_VALUE)
    {
        char buf[MAX_PATH];

        GetModuleFileNameA(NULL, buf, sizeof(buf));

        fs::path def(buf);

        m_defaultDir = def.has_parent_path() ? def.parent_path().string() + "\\" : "";
        m_defaultName = def.has_filename() ? def.filename().string() + "_" + std::to_string(GetCurrentProcessId()) + ".log" : "";

        InitializeCriticalSection(&crit);
    }

    ~CLogger()
    {
        DeleteCriticalSection(&crit);
        CloseHandle(m_hLog);
    }
};