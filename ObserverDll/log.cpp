#include "log.h"
#include "db.h"
#include "observer_dll.h"

namespace logger {

std::string defaultName, defaultDir;
HANDLE File = INVALID_HANDLE_VALUE;

} // namespace logger

bool logger::CreateLogFile(const char* fileDir, const char* fileName)
{
    std::string curProcessImage;
    curProcessImage.reserve(MAX_PATH * 2);

    if (GetModuleFileNameA(0, curProcessImage.data(), MAX_PATH * 2))
    {
        std::filesystem::path defaultLogPath(curProcessImage.c_str());
        defaultDir = (char*)defaultLogPath.parent_path().string().c_str();

        defaultName = (char*)defaultLogPath.filename().string().c_str();
        defaultName += '_' + std::to_string(GetCurrentProcessId()) + ".log";
    }

    std::filesystem::path logPath;

    logPath.concat(fileDir ? fileDir : defaultDir);
    logPath.concat("\\");
    logPath.concat(fileName ? fileName : defaultName);

    HANDLE hFile = CreateFileA((char*)logPath.string().c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    logger::File = hFile;
    return true;
}

bool logger::WriteLogFile(void* data, uint32_t dataSize)
{
    DWORD written = 0;
    return WriteFile(logger::File, data, dataSize, &written, NULL);
}

bool logger::LogFunction(SYSTEMTIME& time, DbFunction& dbFunc, std::vector<std::string>& args, uint32_t* ntstatus)
{
    std::string rawArguments, result;
    rawArguments.clear();

    for (uint32_t i = 0; i < args.size(); i++)
    {
        rawArguments += args[i];
        if (i != args.size() - 1)
        {
            rawArguments += ", ";
        }
    }

    if (ntstatus)
    {
        result = std::format(
            "[{:02d}:{:02d}:{:02d}.{:03d}][{:04x}] {:s} ({:s}) => 0x{:08x};\n",
            time.wHour,
            time.wMinute,
            time.wSecond,
            time.wMilliseconds,
            GetCurrentThreadId(),
            dbFunc.Name.c_str(),
            rawArguments.c_str(),
            *ntstatus);
    }
    else
    {
        result = std::format("[{:02d}:{:02d}:{:02d}.{:03d}][{:04x}] {:s} ({:s});\n",
                             time.wHour,
                             time.wMinute,
                             time.wSecond,
                             time.wMilliseconds,
                             GetCurrentThreadId(),
                             dbFunc.Name.c_str(),
                             rawArguments.c_str());
    }

    return WriteLogFile((char*)result.c_str(), result.length());
}

bool logger::LogEvent(const char* eventName, std::vector<std::string>& args, uint32_t* ntstatus)
{
    std::string rawArguments, result;
    rawArguments.clear();

    for (uint32_t i = 0; i < args.size(); i++)
    {
        rawArguments += args[i];
        if (i != args.size() - 1)
        {
            rawArguments += ", ";
        }
    }

    if (ntstatus)
    {
        result = std::format(
            "#{:s} ({}) => 0x{:08x};\n",
            eventName,
            rawArguments,
            *ntstatus);
    }
    else
    {
        result = std::format(
            "#{:s} ({});\n",
            eventName,
            rawArguments);
    }

    return WriteLogFile((char*)result.c_str(), result.length());
}

bool logger::LogEventWithTime(const char* eventName, std::vector<std::string>& args, uint32_t* ntstatus)
{
    SYSTEMTIME time;
    GetLocalTime(&time);

    std::string rawArguments, result;
    rawArguments.clear();

    for (uint32_t i = 0; i < args.size(); i++)
    {
        rawArguments += args[i];
        if (i != args.size() - 1)
        {
            rawArguments += ", ";
        }
    }

    if (ntstatus)
    {
        result = std::format(
            "[{:02d}:{:02d}:{:02d}.{:03d}][{:04x}] #{:s} ({}) => 0x{:08x};\n",
            time.wHour,
            time.wMinute,
            time.wSecond,
            time.wMilliseconds,
            GetCurrentThreadId(),
            eventName,
            rawArguments,
            *ntstatus);
    }
    else
    {
        result = std::format(
            "[{:02d}:{:02d}:{:02d}.{:03d}][{:04x}] #{:s} ({});\n",
            time.wHour,
            time.wMinute,
            time.wSecond,
            time.wMilliseconds,
            GetCurrentThreadId(),
            eventName,
            rawArguments);
    }

    return WriteLogFile((char*)result.c_str(), result.length());
}