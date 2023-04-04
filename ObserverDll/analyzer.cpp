#include "analyzer.h"

#include <bitset>
#include <format>

#include "memory.h"

namespace analyzer {
fNtQueryInformationFile NtQueryInformationFile =
    reinterpret_cast<fNtQueryInformationFile>(
        GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationFile"));
}

bool analyzer::QueryNameObject(HANDLE value, std::string& name)
{
    ULONG size = 0;
    NTSTATUS status = NtQueryObject((HANDLE)value, ObjectNameInformation, NULL, NULL, &size);

    if (STATUS_INFO_LENGTH_MISMATCH == status && size > 0)
    {
        std::vector<uint8_t> nameVector;
        nameVector.reserve(size);

        status = NtQueryObject((HANDLE)value, ObjectNameInformation, nameVector.data(), size, NULL);

        if (NT_SUCCESS(status))
        {
            UNICODE_STRING* nameUnicodeString = (UNICODE_STRING*)nameVector.data();

            name.resize(nameUnicodeString->Length + 1);

            if (UnicodeToAnsi(nameUnicodeString->Buffer, name.data(), nameUnicodeString->Length + 1, NULL))
            {
                return true;
            }
        }
    }
    return false;
}

bool analyzer::QueryTypeObject(HANDLE value, std::string& type)
{
    ULONG size = 0;
    NTSTATUS status = NtQueryObject((HANDLE)value, ObjectTypeInformation, NULL, NULL, &size);

    if (STATUS_INFO_LENGTH_MISMATCH == status && size > 0)
    {
        std::vector<uint8_t> typeVector;
        typeVector.reserve(size);

        status = NtQueryObject((HANDLE)value, ObjectTypeInformation, typeVector.data(), size, NULL);

        if (NT_SUCCESS(status))
        {
            UNICODE_STRING* typeUnicodeString = (UNICODE_STRING*)typeVector.data();

            type.resize(typeUnicodeString->Length + 1);

            if (UnicodeToAnsi(typeUnicodeString->Buffer, type.data(), typeUnicodeString->Length + 1, NULL))
            {
                return true;
            }
        }
    }
    return false;
}

bool analyzer::QueryProcessImage(HANDLE value, std::string& image)
{
    ULONG size = 0;
    NTSTATUS status =
        NtQueryInformationProcess((HANDLE)value, ProcessImageFileNameWin32, NULL, NULL, &size);

    if (STATUS_INFO_LENGTH_MISMATCH == status && size > 0)
    {
        std::vector<uint8_t> pathBuffer;
        pathBuffer.reserve(size);

        status =
            NtQueryInformationProcess((HANDLE)value, ProcessImageFileNameWin32, pathBuffer.data(), size, NULL);

        if (NT_SUCCESS(status))
        {
            UNICODE_STRING* pathUnicodeString = (UNICODE_STRING*)pathBuffer.data();

            image.resize(pathUnicodeString->Length + 1);

            if (UnicodeToAnsi(pathUnicodeString->Buffer, image.data(), pathUnicodeString->Length + 1, NULL))
            {
                return true;
            }
        }
    }
    return false;
}

void analyzer::GetStringFromConstants(uint32_t value, const std::map<uint32_t, std::string>* constants, std::string& result)
{
    if (value == 0)
    {
        if (constants->contains(value))
        {
            result.append(constants->at(value));
            return;
        }
    }
    else
    {
        bool flag = true;
        for (auto it = constants->begin(); it != constants->end(); it++)
        {
            if (it->first > 0)
            {
                if ((it->first & value) == it->first)
                {
                    if (flag)
                    {
                        result.append(it->second);
                        flag = false;
                        continue;
                    }

                    result.append(" | ");
                    result.append(it->second);
                }
            }
        }
    }
}

void analyzer::GetStringFromEnums(uint32_t value, const std::map<uint32_t, std::string>* enums, std::string& result)
{
    if (enums->contains(value))
    {
        result.append(enums->at(value));
    }
}

bool analyzer::UnicodeToAnsi(wchar_t* src, char* dest, uint32_t destSize, uint32_t* outSize)
{
    int requiredSize =
        WideCharToMultiByte(CP_UTF8, NULL, src, -1, NULL, NULL, NULL, NULL);

    if (outSize)
    {
        *outSize = requiredSize;
        return true;
    }
    else
    {
        if (destSize >= requiredSize)
        {
            WideCharToMultiByte(CP_UTF8, NULL, src, -1, dest, destSize, NULL, NULL);
            return true;
        }
    }
    return false;
}

void analyzer::AnalyzeFunctionArgs(uint32_t* args, config::Type types, uint8_t maxPtr, uint32_t minStrLen, uint32_t maxStrLen, std::vector<std::string>& result)
{
    for (uint32_t i = 0; i < result.size(); i++)
    {
        ArgumentToString(args[i], result[i], types, maxPtr, minStrLen, maxStrLen);
    }
}

void analyzer::ArgumentToString(uint32_t argument, std::string& result, config::Type types, uint8_t ptrMax, uint32_t minStrLen, uint32_t maxStrLen)
{
    result += std::format("0x{:08x}", argument);
    std::string objType;
    config::Type argType =
        analyzer::AnalyzeType(argument, types, objType, minStrLen, maxStrLen);

    if ((bool)operator&<config::Type>(argType, config::Type::TypeAnyHandle))
    {
        std::string objString;
        if (analyzer::TypeToObject(argument, argType, objType, objString))
        {
            result += objString.c_str();
        }
        return;
    }

    if ((bool)operator&<config::Type>(argType, config::Type::TypeUnicodeString))
    {
        std::string ansi;

        ansi.resize(((UNICODE_STRING*)argument)->Length + 1);

        if (UnicodeToAnsi(((UNICODE_STRING*)argument)->Buffer, ansi.data(), ((UNICODE_STRING*)argument)->Length + 1, NULL))
        {
            result += " -> \"";
            result += ansi.c_str();
            result += "\"";
        }
        return;
    }

    if ((bool)operator&<config::Type>(argType, config::Type::TypeAnsiString))
    {
        std::string ansi = ((ANSI_STRING*)argument)->Buffer;
        result += " -> \"";
        result += ansi.c_str();
        result += "\"";
        return;
    }

    if ((bool)operator&<config::Type>(argType, config::Type::TypeCharArray))
    {
        std::string ansi = (char*)argument;
        result += " -> \"";
        result += ansi.c_str();
        result += "\"";
        return;
    }

    if ((bool)operator&<config::Type>(argType, config::Type::TypeWideCharArray))
    {
        std::string ansi;
        uint32_t size = 0;
        if (UnicodeToAnsi((wchar_t*)argument, NULL, NULL, &size))
        {
            ansi.reserve(size);

            if (UnicodeToAnsi((wchar_t*)argument, ansi.data(), size, NULL))
            {
                result += " -> \"";
                result += ansi.c_str();
                result += "\"";
            }
        }
        return;
    }

    if (ptrMax)
    {
        uint32_t szPage = 0;
        if (!memory::IsBadReadAddress((uint32_t*)argument, &szPage) && szPage >= sizeof(uint32_t))
        {
            result += " -> ";
            return ArgumentToString(*(uint32_t*)argument, result, types, --ptrMax, minStrLen, maxStrLen);
        }
    }
}

Type analyzer::AnalyzeType(uint32_t value, Type typeMask, std::string& objName, uint32_t minStrLen, uint32_t maxStrLen)
{
    uint32_t szPage = 0;

    if (value == -1)
    {
        return Type::TypeUnknown;
    }

    if (memory::IsBadReadAddress((void*)value, &szPage))
    {
        if ((bool)operator&<Type>(typeMask, Type::TypeAnyHandle))
        {
            if (QueryTypeObject((HANDLE)value, objName))
            {
                if ((bool)operator&<Type>(typeMask, Type::TypeProcessHandle))
                {
                    if (lstrcmpiA(objName.c_str(), "Process") == 0)
                    {
                        return Type::TypeProcessHandle;
                    }
                }
                if ((bool)operator&<Type>(typeMask, Type::TypeFileHandle))
                {
                    if (lstrcmpiA(objName.c_str(), "File") == 0)
                    {
                        return Type::TypeFileHandle;
                    }
                }
                if ((bool)operator&<Type>(typeMask, Type::TypeRegKeyHandle))
                {
                    if (lstrcmpiA(objName.c_str(), "Key") == 0)
                    {
                        return Type::TypeRegKeyHandle;
                    }
                }
                if ((bool)operator&<Type>(typeMask, Type::TypeSectionHandle))
                {
                    if (lstrcmpiA(objName.c_str(), "Section") == 0)
                    {
                        return Type::TypeSectionHandle;
                    }
                }
                if ((bool)operator&<Type>(typeMask, Type::TypeMutantHandle))
                {
                    if (lstrcmpiA(objName.c_str(), "Mutant") == 0)
                    {
                        return Type::TypeMutantHandle;
                    }
                }
                if ((bool)operator&<Type>(typeMask, Type::TypeThreadHandle))
                {
                    if (lstrcmpiA(objName.c_str(), "Thread") == 0)
                    {
                        return Type::TypeThreadHandle;
                    }
                }
                if ((bool)operator&<Type>(typeMask, Type::TypeEventHandle))
                {
                    if (lstrcmpiA(objName.c_str(), "Event") == 0)
                    {
                        return Type::TypeEventHandle;
                    }
                }
            }
        }
    }
    else
    {
        if ((bool)operator&<Type>(typeMask, Type::TypeUnicodeString))
        {
            if (IsTypeUnicodeString(value, minStrLen, maxStrLen, szPage))
            {
                return Type::TypeUnicodeString;
            }
        }

        if ((bool)operator&<Type>(typeMask, Type::TypeAnsiString))
        {
            if (IsTypeAnsiString(value, minStrLen, maxStrLen, szPage))
            {
                return Type::TypeAnsiString;
            }
        }

        if ((bool)operator&<Type>(typeMask, Type::TypeCharArray))
        {
            if (IsTypeCharArray(value, minStrLen, maxStrLen, 0, &szPage))
            {
                return Type::TypeCharArray;
            }
        }

        if ((bool)operator&<Type>(typeMask, Type::TypeWideCharArray))
        {
            if (IsTypeWideCharArray(value, minStrLen, maxStrLen, 0, &szPage))
            {
                return Type::TypeWideCharArray;
            }
        }
    }

    return Type::TypeUnknown;
}

bool analyzer::IsTypeCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize)
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
                    if (minLength <= len && len <= maxLength)
                    {
                        if (outLength)
                        {
                            *outLength = len;
                        }
                        return true;
                    }
                    return false;
                }
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

bool analyzer::IsTypeWideCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize)
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
                    if (minLength <= len && len <= maxLength)
                    {
                        if (outLength)
                        {
                            *outLength = len;
                        }
                        return true;
                    }
                    return false;
                }
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

bool analyzer::IsTypeUnicodeString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize)
{
    if (memSize > sizeof(UNICODE_STRING))
    {
        uint32_t pageSize = 0;
        if (!memory::IsBadReadAddress(((UNICODE_STRING*)value)->Buffer,
                                      &pageSize))
        {
            uint32_t len = 0;
            if (IsTypeWideCharArray((uint32_t)((UNICODE_STRING*)value)->Buffer,
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

bool analyzer::IsTypeAnsiString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize)
{
    if (memSize > sizeof(ANSI_STRING))
    {
        uint32_t pageSize = 0;
        if (!memory::IsBadReadAddress(((ANSI_STRING*)value)->Buffer, &pageSize))
        {
            uint32_t len = 0;
            if (IsTypeCharArray((uint32_t)((ANSI_STRING*)value)->Buffer, minLength, maxLength, &len, 0))
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

bool analyzer::TypeToObject(uint32_t value, config::Type type, std::string& objType, std::string& result)
{
    if ((bool)operator&<Type>(type, Type::TypeCharArray))
    {
        return false;
    }

    switch (type)
    {
        case Type::TypeProcessHandle:
        {
            uint32_t pid = GetProcessId((HANDLE)value);
            if (pid)
            {
                std::string image;

                if (QueryProcessImage((HANDLE)value, image))
                {
                    result = std::format(" {{{:s}: [{:d}:\"{:s}\"]}}",
                                         objType.c_str(),
                                         pid,
                                         image.c_str());
                    return true;
                }
            }
        }
        default:
        {
            std::string objName;

            if (QueryNameObject((HANDLE)value, objName))
            {
                result = std::format(" {{{:s}: [\"{:s}\"]}}", objType.c_str(), objName.c_str());
                return true;
            }
        }
    }

    return false;
}

bool analyzer::CalculateMD5Hash(uint8_t* data, uint32_t size, std::string& hash)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    DWORD cbHash = 16;

    std::vector<uint8_t> rgbHash;
    rgbHash.resize(cbHash);

    if (CryptAcquireContextA(&hProv,
                             NULL,
                             NULL,
                             PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))
    {
        if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        {
            CryptReleaseContext(hProv, 0);
            return false;
        }

        if (!CryptHashData(hHash, data, size, 0))
        {
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            return false;
        }

        if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash.data(), &cbHash, 0))
        {
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            return HexToString(rgbHash.data(), cbHash, hash);
        }
    }
    return false;
}

bool analyzer::CalculateMD5Hash(const char* filePath, std::string& hash)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    DWORD cbHash = 16;

    std::vector<uint8_t> rgbHash;
    rgbHash.resize(cbHash);

    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (CryptAcquireContextA(&hProv,
                             NULL,
                             NULL,
                             PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))
    {
        if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return false;
        }

        const uint32_t size = 1024;
        uint8_t buffer[size] = {0};

        DWORD readed = 0;

        while (ReadFile(hFile, buffer, size, &readed, NULL))
        {
            if (!readed)
            {
                break;
            }

            if (!CryptHashData(hHash, buffer, size, 0))
            {
                CryptReleaseContext(hProv, 0);
                CryptDestroyHash(hHash);
                CloseHandle(hFile);
                return false;
            }
        }

        CloseHandle(hFile);

        if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash.data(), &cbHash, 0))
        {
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            return HexToString(rgbHash.data(), cbHash, hash);
        }
    }
    return false;
}

bool analyzer::HexToString(uint8_t* byteArray, uint32_t size, std::string& str)
{
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    str.resize(size * 2);
    for (int i = 0; i < size; ++i)
    {
        str[2 * i] = hexmap[(byteArray[i] & 0xF0) >> 4];
        str[2 * i + 1] = hexmap[byteArray[i] & 0x0F];
    }
    return true;
}
