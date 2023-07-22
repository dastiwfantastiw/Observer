#pragma once
#include "events.h"
#include "formater.h"
#include "logger.h"

class CEventArgs
{
private:
    CLogger& m_Logger;

    std::vector<std::string> m_Args;
    std::string m_EventName;

public:
    static const MapFlags mapMemoryAllocFlags;
    static const MapFlags mapMemoryProtectFlags;

    static const MapFlags mapProcessAccessMaskFlags;

    static const MapFlags mapFileAttributesFlags;
    static const MapFlags mapFileShareAccessFlags;
    static const MapFlags mapFileCreateDispositionsFlags;
    static const MapFlags mapFileCreateOptionsFlags;

    static const MapFlags mapKeyCreateDispositionsFlags;
    static const MapFlags mapKeyCreateOptionsFlags;
    static const MapFlags mapKeyTypesFlags;
    static const MapFlags mapKeyValueInfoClass;

    static const MapFlags mapSectionAttribFlags;
    static const MapFlags mapSectionAccessFlags;

    CEventArgs(CLogger& logger, const char* name)
        : m_Logger(logger)
        , m_EventName(name){};

    void AddHandle(HANDLE handle);

    void AddHandle(HANDLE* pHandle);

    void AddProcess(HANDLE handle);

    void AddProcess(HANDLE* pHandle);

    void AddTid(HANDLE handle);

    void AddTid(HANDLE* pHandle);

    void AddStringFlags(const char* name, uint32_t value, const MapFlags* mapconsts);

    void AddStringSize32(const char* name, uint32_t value);

    void AddStringSize32(const char* name, uint32_t* pValue);

    void AddStringSize64(const char* name, uint64_t value);

    void AddStringSize64(const char* name, uint64_t* pValue);

    void AddString(const char* name, const char* value);

    void AddStringUint32(const char* name, uint32_t value);

    void AddStringUint64(const char* name, uint64_t value);

    void AddUnicodeString(const char* name, UNICODE_STRING* value);

    void AddThreadContext(CONTEXT* ctx);

    template<typename T>
    void AddDump(T address, T size);

    bool LogEvent(SYSTEMTIME* time, CDbModule* dbModule, CDbFunction* dbFunc, uint32_t* ntstatus);

private:
    static void GetStringFromMask(uint32_t value, const MapFlags* mapconsts, std::string& result)
    {
        result.clear();

        bool flag = true;

        for (auto c = mapconsts->begin(); c != mapconsts->end(); c++)
        {
            if (!value)
                break;

            if (value & c->first)
            {
                value &= ~c->first;

                if (flag)
                {
                    result.append(c->second);
                    flag = false;
                    continue;
                }

                result += " | ";
                result += c->second;
            }
        }
    }
};

template<typename T>
inline void CEventArgs::AddDump(T address, T size)
{
    std::vector<uint8_t> dump((uint8_t*)address, (uint8_t*)address + size);

    m_Args.push_back(std::format("{}", dump));
}
