#include "logger.h"
#include "database.h"
#include "events.h"

bool CLogger::WriteLog(const void* data, const size_t size)
{
    EnterCriticalSection(&crit);
    DWORD written = 0;
    bool result = WriteFile(m_hLog, data, size, &written, NULL);
    LeaveCriticalSection(&crit);
    return result;
}

bool CLogger::CreateLogFile(const char* path)
{
    fs::path userPath(path);

    std::string logPath;

    logPath.append(userPath.has_parent_path() ? userPath.parent_path().string() : m_defaultDir);

    if (logPath[logPath.length() - 1] != '\\')
    {
        if (logPath[logPath.length() - 1] != '/')
            logPath.append("\\");
    }

    logPath.append(userPath.has_filename() ? userPath.filename().string() : m_defaultName);

    if ((m_hLog = CreateFileA(logPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL)) == INVALID_HANDLE_VALUE)
    {
        return !((m_hLog = CreateFileA(m_defaultName.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL)) == INVALID_HANDLE_VALUE);
    }
    return true;
}