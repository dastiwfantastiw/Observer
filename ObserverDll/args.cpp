#include "args.h"

void CArgs::AnalyzerArguments(uint32_t* args, CDbFunction* dbFunc)
{
    m_Args.clear();
    m_Args.resize(dbFunc->m_Argc);

    int i = 0;

    for (auto a = m_Args.begin(); a != m_Args.end(); a++, i++)
    {
        m_Analyzer.ArgumentToString(args[i], dbFunc, dbFunc->m_MaxPtrRead, *a);
    }
}

bool CArgs::LogFunction(SYSTEMTIME* time, CDbModule* dbModule, CDbFunction* dbFunc, uint32_t* ntstatus)
{
    std::string arguments;

    for (size_t i = 0; i < m_Args.size(); i++)
    {
        arguments += m_Args[i];

        if (i != m_Args.size() - 1)
        {
            arguments += ", ";
        }
    }

    return ntstatus ? m_Logger.LogFormat("[{:02d}:{:02d}:{:02d}.{:03d}][{:x}][{:04x}] <{:s}> {:s} ({:s}) => 0x{:08x};\n",
                                         time->wHour,
                                         time->wMinute,
                                         time->wSecond,
                                         time->wMilliseconds,
                                         GetCurrentProcessId(),
                                         GetCurrentThreadId(),
                                         dbModule->m_Name.c_str(),
                                         dbFunc->m_Name.c_str(),
                                         arguments.c_str(),
                                         *ntstatus)
                    : m_Logger.LogFormat("[{:02d}:{:02d}:{:02d}.{:03d}][{:x}][{:04x}] <{:s}> {:s} ({:s});\n",
                                         time->wHour,
                                         time->wMinute,
                                         time->wSecond,
                                         time->wMilliseconds,
                                         GetCurrentProcessId(),
                                         GetCurrentThreadId(),
                                         dbModule->m_Name.c_str(),
                                         dbFunc->m_Name.c_str(),
                                         arguments.c_str());
}
