#pragma once
#include <Windows.h>

#include <format>
#include <string>
#include <vector>

struct DbFunction;

namespace logger {
extern std::string defaultName, defaultDir;
extern HANDLE File;

bool CreateLogFile(const char* logFileDir, const char* logFileName);
bool WriteLogFile(void* data, uint32_t dataSize);
bool LogFunction(SYSTEMTIME& time, DbFunction& dbFunc, std::vector<std::string>& args, uint32_t* ntstatus);
bool LogEvent(const char* eventName, std::vector<std::string>& args, uint32_t* ntstatus);
bool LogEventWithTime(const char* eventName, std::vector<std::string>& args, uint32_t* ntstatus);

template<typename... Args>
bool Trace(const char* format, Args... args)
{
    int length = std::snprintf(NULL, 0, format, args...);
    if (length)
    {
        char* buf = new char[length + 1];
        std::snprintf(buf, length + 1, format, args...);

        bool result = WriteLogFile(buf, length);
        delete[] buf;
        return result;
    }
    return false;
}

template<typename... Args>
bool TraceFormat(const char* format, Args... args)
{
    std::string result = std::vformat(format, std::make_format_args(std::forward<Args>(args)...));

    return WriteLogFile(result.data(), result.size());
}

template<typename... Args>
bool TraceWithTime(const char* format, Args... args)
{
    SYSTEMTIME time;
    GetLocalTime(&time);

    std::string strFormat = "[%02d:%02d:%02d.%03d][%04x] ";

    strFormat.append(format);

    int length = std::snprintf(NULL, 0, strFormat.c_str(), time.wHour, time.wMinute, time.wSecond, time.wMilliseconds, GetCurrentThreadId(), args...);
    if (length)
    {
        char* buf = new char[length + 1];
        std::snprintf(buf, length + 1, strFormat.c_str(), time.wHour, time.wMinute, time.wSecond, time.wMilliseconds, GetCurrentThreadId(), args...);

        bool result = WriteLogFile(buf, length);
        delete[] buf;
        return result;
    }
    return false;
}

} // namespace logger