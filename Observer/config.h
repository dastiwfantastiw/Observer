#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <stdint.h>
#include <winternl.h>

#include <vector>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace config {

enum
{
    MAGIC = 0xCDDFD6
};

enum Mode : uint8_t
{
    ModeUnknown,
    ModeBefore = 1,
    ModeAfter = 16,
    ModeBoth = ModeBefore | ModeAfter
};

enum Type : uint16_t
{
    TypeUnknown,
    TypeCharArray = 1 << 0,
    TypeWideCharArray = 1 << 1,
    TypeAnsiString = 1 << 2,
    TypeUnicodeString = 1 << 3,
    TypeProcessHandle = 1 << 4,
    TypeFileHandle = 1 << 5,
    TypeRegKeyHandle = 1 << 6,
    TypeThreadHandle = 1 << 7,
    TypeSectionHandle = 1 << 8,
    TypeMutantHandle = 1 << 9,
    TypeEventHandle = 1 << 10,
    TypeAnyHandle = TypeProcessHandle | TypeFileHandle | TypeRegKeyHandle |
                    TypeThreadHandle | TypeSectionHandle | TypeMutantHandle |
                    TypeEventHandle,
    TypeStrings =
        TypeCharArray | TypeWideCharArray | TypeAnsiString | TypeUnicodeString
};

template<class T>
inline T operator|(T a, T b)
{
    return (T)((uint32_t)a | (uint32_t)b);
}
template<class T>
inline T operator&(T a, T b)
{
    return (T)((uint32_t)a & (uint32_t)b);
}

template<class T>
inline T& operator|=(T& a, T b)
{
    return (T&)((uint32_t&)a |= (uint32_t)b);
}

template<class T>
inline T& operator&=(T& a, T b)
{
    return (T&)((uint32_t&)a &= (uint32_t)b);
}

template<typename T, typename T2 = T>
std::vector<T> operator+(std::vector<T> const& x, std::vector<T2> const& y)
{
    std::vector<T> vec;
    vec.reserve(x.size() + y.size());
    vec.insert(vec.end(), x.begin(), x.end());
    vec.insert(vec.end(), y.begin(), y.end());
    return vec;
}

template<typename T, typename T2 = T>
std::vector<T>& operator+=(std::vector<T>& x, const std::vector<T2>& y)
{
    x.reserve(x.size() + y.size());
    x.insert(x.end(), y.begin(), y.end());
    return x;
}

// Binary config

#pragma pack(push, 1)
struct Header
{
    uint32_t Magic;
    uint32_t Size;
};

struct FunctionData
{
    uint32_t FuncHash;
    bool Enabled;
    bool EventsEnabled;
    Mode Mode;
    Type Types;
    uint8_t MaxPtr;
    uint32_t MinStrLen;
    uint32_t MaxStrLen;
};

struct ModuleData
{
    uint32_t ModuleHash;
    bool EnabledAll;
    bool EventsEnabledAll;
    Mode ModeAll;
    Type TypeAll;
    uint8_t MaxPtrAll;
    uint32_t MinStrLenAll;
    uint32_t MaxStrLenAll;
    uint8_t FuncCount;
};

struct BinaryConfig
{
    Header Header;
    HANDLE MapHandle;
    char LogPath[MAX_PATH];

    uint8_t ModulesCount;
    ModuleData Modules[1];
    // FunctionData Functions[1];
};
#pragma pack(pop)


template<typename T1 = json, typename T2>
bool GetFromJson(const char* name, const char* typeName, T1& source, T2& dest)
{
    if (source.contains(name))
    {
        if (lstrcmpiA(source.at(name).type_name(), typeName) == 0)
        {
            source.at(name).get_to<T2>(dest);
            return true;
        }
    }
    return false;
}
} // namespace config