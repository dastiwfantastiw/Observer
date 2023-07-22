#include "analyzer.h"
#include "memory.h"

#include <ntstatus.h>

template<class T>
inline T& operator&=(T& a, T b)
{
    return (T&)((uint32_t&)a &= (uint32_t)b);
}

fNtQueryInformationFile CAnalyzer::NtQueryInformationFile = (fNtQueryInformationFile)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationFile");

DataTypes CAnalyzer::AnalyzeType(uint32_t value, CSettings* sets, std::string& objectType)
{
    uint32_t pgSize = 0;

    if (memory::IsBadReadAddress((void*)value, &pgSize))
    {
        if (sets->m_DataTypes & DATA_TYPE_HANDLES)
        {
            if (QueryObject(ObjectTypeInformation, (HANDLE)value, objectType))
            {
                if ((sets->m_DataTypes & DATA_TYPE_PROCESS) && (lstrcmpiA("Process", objectType.c_str()) == 0))
                    return DATA_TYPE_PROCESS;

                if ((sets->m_DataTypes & DATA_TYPE_FILE) && (lstrcmpiA("File", objectType.c_str()) == 0))
                    return DATA_TYPE_FILE;

                if ((sets->m_DataTypes & DATA_TYPE_REG_KEY) && (lstrcmpiA("Key", objectType.c_str()) == 0))
                    return DATA_TYPE_REG_KEY;

                if ((sets->m_DataTypes & DATA_TYPE_THREAD) && (lstrcmpiA("Thread", objectType.c_str()) == 0))
                    return DATA_TYPE_THREAD;

                if ((sets->m_DataTypes & DATA_TYPE_SECTION) && (lstrcmpiA("Section", objectType.c_str()) == 0))
                    return DATA_TYPE_SECTION;

                if ((sets->m_DataTypes & DATA_TYPE_MUTANT) && (lstrcmpiA("Mutant", objectType.c_str()) == 0))
                    return DATA_TYPE_MUTANT;

                if ((sets->m_DataTypes & DATA_TYPE_EVENT) && (lstrcmpiA("Event", objectType.c_str()) == 0))
                    return DATA_TYPE_EVENT;
            }
        }
    }
    else
    {
        if ((sets->m_DataTypes & DATA_TYPE_STRINGS) && sets->m_MinStrLen && sets->m_MaxStrLen)
        {
            if (sets->m_DataTypes & DATA_TYPE_UNICODE_STRING)
            {
                if (IsUnicodeString(value, sets->m_MinStrLen, sets->m_MaxStrLen, pgSize))
                    return DATA_TYPE_UNICODE_STRING;
            }

            if (sets->m_DataTypes & DATA_TYPE_ANSI_STRING)
            {
                if (IsAnsiString(value, sets->m_MinStrLen, sets->m_MaxStrLen, pgSize))
                    return DATA_TYPE_ANSI_STRING;
            }

            if (sets->m_DataTypes & DATA_TYPE_CHAR)
            {
                if (IsCharArray(value, sets->m_MinStrLen, sets->m_MaxStrLen, 0, &pgSize))
                    return DATA_TYPE_CHAR;
            }

            if (sets->m_DataTypes & DATA_TYPE_WIDECHAR)
            {
                if (IsWideCharArray(value, sets->m_MinStrLen, sets->m_MaxStrLen, 0, &pgSize))
                    return DATA_TYPE_WIDECHAR;
            }
        }
    }

    return DATA_TYPE_NONE;
}

bool CAnalyzer::QueryObject(OBJECT_INFORMATION_CLASS objectClass, HANDLE value, std::string& output)
{
    ULONG size = 0;
    NTSTATUS status = NtQueryObject((HANDLE)value, objectClass, NULL, NULL, &size);

    if (STATUS_INFO_LENGTH_MISMATCH == status && size > 0)
    {
        std::vector<uint8_t> vec;
        vec.reserve(size);

        status = NtQueryObject((HANDLE)value, objectClass, vec.data(), size, NULL);

        if (NT_SUCCESS(status))
        {
            UNICODE_STRING* us = (UNICODE_STRING*)vec.data();

            output.resize(us->Length + 1);

            if (UnicodeToAnsi(us->Buffer, output.data(), us->Length + 1, NULL))
            {
                return true;
            }
        }
    }
    return false;
}

bool CAnalyzer::UnicodeToAnsi(wchar_t* source, char* dest, uint32_t destSize, uint32_t* outSize)
{
    uint32_t requiredSize = WideCharToMultiByte(CP_UTF8, NULL, source, -1, NULL, NULL, NULL, NULL);

    if (outSize)
    {
        *outSize = requiredSize;
        return true;
    }

    if (destSize >= requiredSize)
    {
        WideCharToMultiByte(CP_UTF8, NULL, source, -1, dest, destSize, NULL, NULL);
        return true;
    }

    return false;
}

bool CAnalyzer::IsCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize)
{
    uint32_t szPage = 0;

    if (!memSize)
    {
        if (memory::IsBadReadAddress((void*)value, &szPage))
        {
            return false;
        }
    }
    else
    {
        szPage = *memSize;
    }

    if (minLength > szPage)
    {
        return false;
    }

    uint32_t len = 0;
    unsigned char* charPointer = (unsigned char*)(value);

    while (len <= szPage)
    {
        if (len == szPage)
        {
            uint32_t nextPageSize = 0;
            if (memory::IsBadReadAddress(&charPointer[len + 1], &nextPageSize))
            {
                return false;
            }
            szPage += nextPageSize;
        }

        switch (charPointer[len])
        {
            case '\a':
            case '\b':
            case '\t':
            case '\n':
            case '\v':
            case '\f':
            case '\r':
                len++;
                continue;
            case '\0':
            {
                if (charPointer[len] == '\0')
                {
                    if (minLength < len && len <= maxLength)
                    {
                        if (outLength)
                        {
                            *outLength = len;
                        }
                        return true;
                    }
                    return false;
                }
                break;
            }
            default:
            {
                if (0x7f < charPointer[len] || charPointer[len] < 0x20)
                {
                    return false;
                }
                len++;
                continue;
            }
        }
    }
    return false;
}

bool CAnalyzer::IsWideCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize)
{
    uint32_t szPage = 0;

    if (!memSize)
    {
        if (memory::IsBadReadAddress((void*)value, &szPage))
        {
            return false;
        }
    }
    else
    {
        szPage = *memSize;
    }

    if (minLength > szPage)
    {
        return false;
    }

    uint32_t len = 0;
    wchar_t* wcharPointer = (wchar_t*)(value);

    while (len <= szPage)
    {
        if (len == szPage)
        {
            uint32_t nextPageSize = 0;
            if (memory::IsBadReadAddress(&wcharPointer[len + 1], &nextPageSize))
            {
                return false;
            }
            szPage += nextPageSize;
        }

        switch (wcharPointer[len])
        {
            case '\a\0':
            case '\b\0':
            case '\t\0':
            case '\n\0':
            case '\v\0':
            case '\f\0':
            case '\r\0':
                len++;
                continue;
            case '\0\0':
            {
                if (wcharPointer[len] == '\0\0')
                {
                    if (minLength < len && len <= maxLength)
                    {
                        if (outLength)
                        {
                            *outLength = len;
                        }
                        return true;
                    }
                    return false;
                }
                break;
            }
            default:
            {
                if (0x007f < wcharPointer[len] || wcharPointer[len] < 0x0020)
                {
                    return false;
                }
                len++;
                continue;
            }
        }
    }
    return false;
}

bool CAnalyzer::IsUnicodeString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize)
{
    if (memSize > sizeof(UNICODE_STRING))
    {
        uint32_t pageSize = 0;
        if (!memory::IsBadReadAddress(((UNICODE_STRING*)value)->Buffer,
                                      &pageSize))
        {
            uint32_t len = 0;
            if (IsWideCharArray((uint32_t)((UNICODE_STRING*)value)->Buffer,
                                minLength,
                                maxLength,
                                &len,
                                0))
            {
                if (len * 2 == ((UNICODE_STRING*)value)->Length)
                {
                    return true;
                }
            }
        }
    }
    return false;
}

bool CAnalyzer::IsAnsiString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize)
{
    if (memSize > sizeof(ANSI_STRING))
    {
        uint32_t pageSize = 0;
        if (!memory::IsBadReadAddress(((ANSI_STRING*)value)->Buffer, &pageSize))
        {
            uint32_t len = 0;
            if (IsCharArray((uint32_t)((ANSI_STRING*)value)->Buffer, minLength, maxLength, &len, 0))
            {
                if (len == ((UNICODE_STRING*)value)->Length)
                {
                    return true;
                }
            }
        }
    }
    return false;
}

bool CAnalyzer::ObjectToString(HANDLE value, DataTypes type, std::string& objectType, std::string& result)
{
    if (type == DATA_TYPE_PROCESS)
    {
        if (value == INVALID_HANDLE_VALUE)
            return false;

        uint32_t pid = GetProcessId((HANDLE)value);

        if (pid)
        {
            std::string image;

            if (QueryProcessImage(value, image))
            {
                result = std::format(" {{{:s}: [{:x}:\"{:s}\"]}}", objectType.c_str(), pid, image.c_str());
                return true;
            }
        }
    }

    if (type == DATA_TYPE_THREAD)
    {
        uint32_t tid = GetThreadId((HANDLE)value);

        if (tid)
        {
            uint32_t pid = GetProcessIdOfThread((HANDLE)value);

            if (pid)
            {
                result = std::format("{{{:s}: [\"{:x} in {:x}\"]}}", objectType.c_str(), tid, pid);
                return true;
            }
        }
    }

    std::string objectName;

    if (QueryObject(ObjectNameInformation, value, objectName))
    {
        result = std::format("{{{:s}: [\"{:s}\"]}}", objectType.c_str(), objectName.c_str());
        return true;
    }

    return false;
}

bool CAnalyzer::ArgumentToString(uint32_t value, CSettings* sets, uint8_t readPtr, std::string& result)
{
    result += std::format("0x{:08x}", value);

    std::string objectType;
    DataTypes argType = AnalyzeType(value, sets, objectType);

    if (argType & DATA_TYPE_HANDLES)
    {
        std::string object;

        if (ObjectToString((HANDLE)value, argType, objectType, object))
        {
            result += " " + object;
            return true;
        }
    }

    if (argType & DATA_TYPE_STRINGS)
    {
        if (argType & DATA_TYPE_UNICODE_STRING)
        {
            std::string ansi;
            ansi.resize(((UNICODE_STRING*)value)->Length + 1);

            if (UnicodeToAnsi(((UNICODE_STRING*)value)->Buffer, ansi.data(), ((UNICODE_STRING*)value)->Length + 1, NULL))
            {
                result += " -> \"";
                result += ansi.c_str();
                result += "\"";
                return true;
            }
        }

        if (argType & DATA_TYPE_ANSI_STRING)
        {
            result += " -> \"";
            result += ((ANSI_STRING*)value)->Buffer;
            result += "\"";
            return true;
        }

        if (argType & DATA_TYPE_WIDECHAR)
        {
            std::string ansi;
            uint32_t size = 0;
            if (UnicodeToAnsi((wchar_t*)value, NULL, NULL, &size))
            {
                ansi.resize(size + 1);

                if (UnicodeToAnsi((wchar_t*)value, ansi.data(), size, NULL))
                {
                    result += " -> \"";
                    result += ansi.c_str();
                    result += "\"";
                    return true;
                }
            }
        }

        if (argType & DATA_TYPE_CHAR)
        {
            result += " -> \"";
            result += (char*)value;
            result += "\"";
            return true;
        }
    }

    uint32_t pgSize = 0;

    if (readPtr && !memory::IsBadReadAddress((void*)value, &pgSize) && pgSize >= sizeof(uint32_t*))
    {
        result += " -> ";
        return ArgumentToString(*(uint32_t*)value, sets, --readPtr, result);
    }

    return true;
}

bool CAnalyzer::QueryProcessImage(HANDLE value, std::string& output)
{
    ULONG size = 0;
    NTSTATUS status = NtQueryInformationProcess((HANDLE)value, ProcessImageFileNameWin32, NULL, NULL, &size);

    if (STATUS_INFO_LENGTH_MISMATCH == status && size > 0)
    {
        std::vector<uint8_t> vec;
        vec.reserve(size);

        status =
            NtQueryInformationProcess((HANDLE)value, ProcessImageFileNameWin32, vec.data(), size, NULL);

        if (NT_SUCCESS(status))
        {
            UNICODE_STRING* us = (UNICODE_STRING*)vec.data();

            output.resize(us->Length + 1);

            if (UnicodeToAnsi(us->Buffer, (char*)output.data(), us->Length + 1, NULL))
            {
                return true;
            }
        }
    }
    return false;
}
