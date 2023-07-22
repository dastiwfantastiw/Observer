#pragma once
#include "config.h"
#include "logger.h"
#include "defines.h"

#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

class CAnalyzer final
{
private:
    CLogger& m_Logger;
    static fNtQueryInformationFile NtQueryInformationFile;

public:
    CAnalyzer(CLogger& logger)
        : m_Logger(logger){};

    ~CAnalyzer(){};

    DataTypes AnalyzeType(uint32_t value, CSettings* sets, std::string& objectType);
    bool ArgumentToString(uint32_t value, CSettings* sets, uint8_t readPtr, std::string& result);

    static bool QueryObject(OBJECT_INFORMATION_CLASS objectClass, HANDLE value, std::string& output);
    static bool QueryProcessImage(HANDLE value, std::string& output);
    static bool ObjectToString(HANDLE value, DataTypes type, std::string& objectType, std::string& result);
    static bool UnicodeToAnsi(wchar_t* source, char* dest, uint32_t destSize, uint32_t* outSize);

    bool IsCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize);
    bool IsWideCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize);

    bool IsUnicodeString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize);
    bool IsAnsiString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize);
};