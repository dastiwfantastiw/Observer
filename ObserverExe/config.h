#pragma once
#include "hash.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

#define OBSERVER_CONFIG_MAGIC 0x39C7068A

#define MAKE_VERSION(major, minor) ((major & 0xff) << 8 | (minor & 0xff))
#define OBSERVER_CONFIG_VERSION MAKE_VERSION(1, 3)

class CBinaryConfig
{
private:
    std::vector<uint8_t> m_vec;

public:
    CBinaryConfig(){};
    ~CBinaryConfig(){};

    CBinaryConfig(CBinaryConfig* ptr, uint32_t size)
    {
        m_vec.resize(size);
        m_vec.insert(m_vec.begin(), (uint8_t*)ptr, (uint8_t*)ptr + size);
    }

    CBinaryConfig(void* data, uint32_t size)
    {
        m_vec.insert(m_vec.begin(), (uint8_t*)data, (uint8_t*)data + size);
    }

    void PushBack(void* data, uint32_t size)
    {
        m_vec.insert(m_vec.end(), (uint8_t*)data, (uint8_t*)data + size);
    }

    bool PopFront(void* data, uint32_t size)
    {
        if (!m_vec.empty() && m_vec.size() >= size)
        {
            if (!memcpy_s((uint8_t*)data, size, m_vec.data(), size))
            {
                m_vec.erase(m_vec.begin(), m_vec.begin() + size);
                return true;
            }
        }
        return false;
    }

    const uint8_t* data() const
    {
        return m_vec.data();
    }

    const size_t size() const
    {
        return m_vec.size();
    }

    bool SaveToFile(const char* path)
    {
        HANDLE hFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
        if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
            return false;

        if (WriteFile(hFile, m_vec.data(), m_vec.size(), NULL, NULL))
        {
            CloseHandle(hFile);
            return true;
        }

        CloseHandle(hFile);
        return false;
    }

    bool LoadFromFile(const char* path)
    {
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
        if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
            return false;

        uint32_t fileSize = GetFileSize(hFile, NULL);

        m_vec.resize(fileSize);

        if (ReadFile(hFile, m_vec.data(), fileSize, NULL, NULL))
        {
            CloseHandle(hFile);
            return true;
        }

        CloseHandle(hFile);
        return false;
    }
};

class IBinarySerializable
{
public:
    IBinarySerializable(){};
    virtual ~IBinarySerializable(){};

    virtual void ToBinary(CBinaryConfig& obj) = 0;
    virtual bool FromBinary(CBinaryConfig& obj) = 0;
};

enum ProcModes : uint8_t
{
    PROCESS_MODE_NONE,
    PROCESS_MODE_PRE_EXEC = 1 << 0,
    PROCESS_MODE_POST_EXEC = 1 << 1
};

NLOHMANN_JSON_SERIALIZE_ENUM(ProcModes, {{PROCESS_MODE_NONE, nullptr}, {PROCESS_MODE_PRE_EXEC, "preExec"}, {PROCESS_MODE_POST_EXEC, "postExec"}})

enum DataTypes : uint16_t
{
    DATA_TYPE_NONE,
    DATA_TYPE_CHAR = 1 << 0,
    DATA_TYPE_WIDECHAR = 1 << 1,
    DATA_TYPE_ANSI_STRING = 1 << 2,
    DATA_TYPE_UNICODE_STRING = 1 << 3,
    DATA_TYPE_PROCESS = 1 << 4,
    DATA_TYPE_FILE = 1 << 5,
    DATA_TYPE_REG_KEY = 1 << 6,
    DATA_TYPE_THREAD = 1 << 7,
    DATA_TYPE_SECTION = 1 << 8,
    DATA_TYPE_MUTANT = 1 << 9,
    DATA_TYPE_EVENT = 1 << 10,
    DATA_TYPE_HANDLES = DATA_TYPE_PROCESS | DATA_TYPE_FILE | DATA_TYPE_REG_KEY | DATA_TYPE_THREAD | DATA_TYPE_SECTION | DATA_TYPE_MUTANT | DATA_TYPE_EVENT,
    DATA_TYPE_STRINGS = DATA_TYPE_CHAR | DATA_TYPE_WIDECHAR | DATA_TYPE_ANSI_STRING | DATA_TYPE_UNICODE_STRING
};

NLOHMANN_JSON_SERIALIZE_ENUM(DataTypes,
                             {{DATA_TYPE_NONE, nullptr},
                              {DATA_TYPE_CHAR, "chararray"},
                              {DATA_TYPE_WIDECHAR, "wchararray"},
                              {DATA_TYPE_ANSI_STRING, "ansistring"},
                              {DATA_TYPE_UNICODE_STRING, "unicodestring"},
                              {DATA_TYPE_PROCESS, "process"},
                              {DATA_TYPE_FILE, "file"},
                              {DATA_TYPE_REG_KEY, "key"},
                              {DATA_TYPE_THREAD, "thread"},
                              {DATA_TYPE_SECTION, "section"},
                              {DATA_TYPE_MUTANT, "mutant"},
                              {DATA_TYPE_EVENT, "event"},
                              {DATA_TYPE_HANDLES, "handles"},
                              {DATA_TYPE_STRINGS, "strings"}})

template<typename T>
bool GetValueFromJson(const json& j, const char* name, const char* typeName, T& dest)
{
    if (!j.contains(name))
        return false;

    if (lstrcmpA(j.at(name).type_name(), typeName) == 0)
    {
        j.at(name).get_to<T>(dest);
        return true;
    }

    return false;
}

class CSettings: public IBinarySerializable
{
public:
#pragma pack(push, 1)
    uint32_t m_MaxStrLen;
    uint32_t m_MinStrLen;
    uint8_t m_MaxPtrRead;

    DataTypes m_DataTypes;
    ProcModes m_ProcMode;

    bool m_IsEnabled;
    bool m_IsEventEnabled;
#pragma pack(pop)

    CSettings()
        : m_MaxStrLen(0)
        , m_MinStrLen(0)
        , m_MaxPtrRead(0)
        , m_DataTypes(DataTypes::DATA_TYPE_NONE)
        , m_ProcMode(ProcModes::PROCESS_MODE_NONE)
        , m_IsEnabled(false)
        , m_IsEventEnabled(false){};

    virtual ~CSettings(){};

    void ToBinary(CBinaryConfig& obj) override
    {
        obj.PushBack(&m_MaxStrLen, sizeof(m_MaxStrLen));
        obj.PushBack(&m_MinStrLen, sizeof(m_MinStrLen));
        obj.PushBack(&m_MaxPtrRead, sizeof(m_MaxPtrRead));
        obj.PushBack(&m_DataTypes, sizeof(m_DataTypes));
        obj.PushBack(&m_ProcMode, sizeof(m_ProcMode));
        obj.PushBack(&m_IsEnabled, sizeof(m_IsEnabled));
        obj.PushBack(&m_IsEventEnabled, sizeof(m_IsEventEnabled));
    };

    bool FromBinary(CBinaryConfig& obj) override
    {
        if (obj.PopFront(&m_MaxStrLen, sizeof(m_MaxStrLen)) &&
            obj.PopFront(&m_MinStrLen, sizeof(m_MinStrLen)) &&
            obj.PopFront(&m_MaxPtrRead, sizeof(m_MaxPtrRead)) &&
            obj.PopFront(&m_DataTypes, sizeof(m_DataTypes)) &&
            obj.PopFront(&m_ProcMode, sizeof(m_ProcMode)) &&
            obj.PopFront(&m_IsEnabled, sizeof(m_IsEnabled)) &&
            obj.PopFront(&m_IsEventEnabled, sizeof(m_IsEventEnabled)))
            return true;
        return false;
    }

    friend void from_json(const json& j, CSettings& obj)
    {
        GetValueFromJson<uint32_t>(j, "maxStrLen", "number", obj.m_MaxStrLen);
        GetValueFromJson<uint32_t>(j, "minStrLen", "number", obj.m_MinStrLen);
        GetValueFromJson<uint8_t>(j, "maxPtrRead", "number", obj.m_MaxPtrRead);

        json::array_t arrTypes, arrMode;

        obj.m_DataTypes = DATA_TYPE_NONE;
        obj.m_ProcMode = PROCESS_MODE_NONE;

        GetValueFromJson<json::array_t>(j, "dataType", "array", arrTypes);
        for (auto it = arrTypes.begin(); it != arrTypes.end(); it++)
        {
            obj.m_DataTypes = (DataTypes)((uint32_t)it->get<DataTypes>() | (uint32_t)obj.m_DataTypes);
        }

        GetValueFromJson<json::array_t>(j, "procMode", "array", arrMode);
        for (auto it = arrMode.begin(); it != arrMode.end(); it++)
        {
            obj.m_ProcMode = (ProcModes)((uint32_t)it->get<ProcModes>() | (uint32_t)obj.m_ProcMode);
        }

        GetValueFromJson<bool>(j, "isEnabled", "boolean", obj.m_IsEnabled);
        GetValueFromJson<bool>(j, "isEventEnabled", "boolean", obj.m_IsEventEnabled);
    }
};

class CFunction: public CSettings
{
public:
    CFunction(CSettings& settings)
        : CSettings(settings){};

    CFunction(){};
    virtual ~CFunction(){};

    void ToBinary(CBinaryConfig& obj) override
    {
        CSettings::ToBinary(obj);
    }

    bool FromBinary(CBinaryConfig& obj) override
    {
        return CSettings::FromBinary(obj);
    }

    friend void from_json(const json& j, CFunction& obj)
    {
        from_json(j, (CSettings&)obj);
    }
};

typedef std::map<uint32_t, CFunction> FuncsContainer;
class CModule: public CSettings
{
public:
#pragma pack(push, 1)
    bool m_IsTraceAll;
#pragma pack(pop)

    FuncsContainer m_Functions;

    CModule()
        : m_IsTraceAll(false){};
    virtual ~CModule(){};

    void ToBinary(CBinaryConfig& obj) override
    {
        obj.PushBack(&m_IsTraceAll, sizeof(m_IsTraceAll));

        uint16_t funcsCount = m_Functions.size() & 0xffff;
        obj.PushBack(&funcsCount, sizeof(funcsCount));

        CSettings::ToBinary(obj);

        uint32_t funcHash = 0;

        for (auto func = m_Functions.begin(); func != m_Functions.end(); func++)
        {
            funcHash = func->first;

            obj.PushBack(&funcHash, sizeof(funcHash));
            func->second.ToBinary(obj);
        }
    }

    bool FromBinary(CBinaryConfig& obj) override
    {
        obj.PopFront(&m_IsTraceAll, sizeof(m_IsTraceAll));

        uint16_t funcsCount = 0;
        obj.PopFront(&funcsCount, sizeof(funcsCount));

        if (!CSettings::FromBinary(obj))
            return false;

        if (funcsCount)
        {
            uint32_t funcHash = 0;

            for (size_t i = 0; i < funcsCount; i++)
            {
                obj.PopFront(&funcHash, sizeof(funcHash));

                CFunction func;
                if (!func.FromBinary(obj))
                    return false;

                m_Functions[funcHash] = func;
            }
        }
        return true;
    }

    friend void from_json(const json& j, CModule& obj)
    {
        GetValueFromJson<bool>(j, "isTraceAll", "boolean", obj.m_IsTraceAll);

        json::object_t settings, funcs;

        if (GetValueFromJson<json::object_t>(j, "settings", "object", settings))
        {
            from_json(settings, static_cast<CSettings&>(obj));
        }

        if (GetValueFromJson<json::object_t>(j, "functions", "object", funcs))
        {
            if (!funcs.empty())
            {
                CFunction function(obj);

                for (auto f = funcs.begin(); f != funcs.end(); f++)
                {
                    if (GetValueFromJson<json::object_t>(f->second, "settings", "object", settings))
                    {
                        from_json(settings, function);
                    }

                    obj.m_Functions[adler32(f->first.c_str(), f->first.length())] = function;
                }
            }
        }
    }
};

typedef std::map<uint32_t, CModule> ModuleContainer;
class CConfig: public IBinarySerializable
{
public:
#pragma pack(push, 1)
    uint32_t m_Magic;
    uint16_t m_Version;
    HANDLE m_DllHandle;
#pragma pack(pop)
    std::string m_LogPath;

protected:
    ModuleContainer m_Modules;

public:
    CConfig()
        : m_Magic(OBSERVER_CONFIG_MAGIC)
        , m_Version(OBSERVER_CONFIG_VERSION)
        , m_DllHandle(INVALID_HANDLE_VALUE){};

    virtual ~CConfig(){};

    void ToBinary(CBinaryConfig& obj) override
    {
        obj.PushBack(&m_Magic, sizeof(m_Magic));
        obj.PushBack(&m_Version, sizeof(m_Version));
        obj.PushBack(&m_DllHandle, sizeof(m_DllHandle));

        uint16_t logLen = m_LogPath.length() & 0xffff;
        obj.PushBack(&logLen, sizeof(logLen));
        obj.PushBack((char*)m_LogPath.c_str(), logLen);

        uint8_t moduleCount = m_Modules.size() & 0xff;

        obj.PushBack(&moduleCount, sizeof(moduleCount));

        if (moduleCount)
        {
            uint32_t moduleHash = 0;

            for (auto module = m_Modules.begin(); module != m_Modules.end(); module++)
            {
                moduleHash = module->first;

                obj.PushBack(&moduleHash, sizeof(moduleHash));

                module->second.ToBinary(obj);
            }
        }
    }

    bool FromBinary(CBinaryConfig& obj) override
    {
        if (!obj.PopFront(&m_Magic, sizeof(m_Magic)))
            return false;

        if (!obj.PopFront(&m_Version, sizeof(m_Version)))
            return false;

        if (obj.PopFront(&m_DllHandle, sizeof(m_DllHandle)))
        {
            uint16_t logLen = 0;

            if (!obj.PopFront(&logLen, sizeof(logLen)))
                return false;

            m_LogPath.clear();
            m_LogPath.resize(logLen);

            if (!obj.PopFront((char*)m_LogPath.data(), logLen))
                return false;

            uint8_t moduleCount = 0;

            if (!obj.PopFront(&moduleCount, sizeof(moduleCount)))
                return false;

            if (moduleCount)
            {
                uint32_t moduleHash = 0;

                for (size_t i = 0; i < moduleCount; i++)
                {
                    if (!obj.PopFront(&moduleHash, sizeof(moduleHash)))
                        return false;

                    CModule mod;
                    if (!mod.FromBinary(obj))
                        return false;

                    m_Modules[moduleHash] = mod;
                }
            }
            return true;
        }
        return false;
    }

    bool LoadFromJson(const char* path)
    {
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            uint32_t fSize = GetFileSize(hFile, NULL);

            char* jsonContent = (char*)calloc(fSize + 1, 1);
            if (jsonContent)
            {
                if (!ReadFile(hFile, jsonContent, fSize, NULL, NULL))
                {
                    CloseHandle(hFile);
                    free(jsonContent);
                    return false;
                }

                json j = json::parse(jsonContent, nullptr, false);
                if (!j.is_discarded())
                {
                    *this = j.get<CConfig>();
                    CloseHandle(hFile);
                    free(jsonContent);
                    return true;
                }

                CloseHandle(hFile);
                free(jsonContent);
            }
        }
        return false;
    }

    friend void from_json(const json& j, CConfig& obj)
    {
        json::object_t observerObj;

        if (GetValueFromJson<json::object_t>(j, "observer", "object", observerObj))
        {
            GetValueFromJson<std::string>(observerObj, "log", "string", obj.m_LogPath);

            json::object_t syscallsObj;

            if (GetValueFromJson<json::object_t>(observerObj, "syscalls", "object", syscallsObj))
            {
                if (syscallsObj.size() > 0)
                {
                    json::object_t moduleObj;

                    for (auto mod = syscallsObj.begin(); mod != syscallsObj.end(); mod++)
                    {
                        if (!mod->second.is_object())
                            continue;

                        CModule module;
                        from_json(mod->second, module);

                        std::filesystem::path stemModuleName(mod->first);

                        std::string moduleName = stemModuleName.stem().string();
                        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

                        obj.m_Modules[adler32(moduleName.c_str(), moduleName.length())] = module;
                    }
                }
            }
        }
    }

    friend class CDataBase;
};