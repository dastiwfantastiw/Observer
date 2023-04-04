#pragma once
#include "../Observer/config.h"

#pragma comment(lib, "ntdll.lib")

#ifndef ObjectNameInformation
#    define ObjectNameInformation (OBJECT_INFORMATION_CLASS)1
#endif // !ObjectNameInformation

#define ProcessImageFileNameWin32 (PROCESSINFOCLASS)43
#define FileNameInformation (FILE_INFORMATION_CLASS)9

typedef struct _FILE_NAME_INFORMATION
{
    ULONG FileNameLength;
    WCHAR FileName[MAX_PATH];

} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef NTSTATUS(NTAPI* fNtQueryInformationFile)(
    HANDLE FileHandle, IO_STATUS_BLOCK* IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

using namespace config;

namespace analyzer {
extern fNtQueryInformationFile NtQueryInformationFile;

Type AnalyzeType(uint32_t value, Type typeMask, std::string& objName, uint32_t minStrLen, uint32_t maxStrLen);

void AnalyzeFunctionArgs(uint32_t* args, config::Type types, uint8_t maxPtr, uint32_t minStrLen, uint32_t maxStrLen, std::vector<std::string>& result);

void ArgumentToString(uint32_t argument, std::string& result, config::Type types, uint8_t ptrMax, uint32_t minStrLen, uint32_t maxStrLen);

bool QueryNameObject(HANDLE value, std::string& name);
bool QueryTypeObject(HANDLE value, std::string& type);
bool QueryProcessImage(HANDLE value, std::string& image);

void GetStringFromConstants(uint32_t value, const std::map<uint32_t, std::string>* constants, std::string& result);
void GetStringFromEnums(uint32_t value, const std::map<uint32_t, std::string>* enums, std::string& result);

bool UnicodeToAnsi(wchar_t* src, char* dest, uint32_t destSize, uint32_t* outSize);

bool IsTypeCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize);

bool IsTypeWideCharArray(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t* outLength, uint32_t* memSize);

bool IsTypeUnicodeString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize);
bool IsTypeAnsiString(uint32_t value, uint32_t minLength, uint32_t maxLength, uint32_t memSize);

bool TypeToObject(uint32_t value, config::Type type, std::string& objType, std::string& result);

bool CalculateMD5Hash(uint8_t* data, uint32_t size, std::string& hash);
bool CalculateMD5Hash(const char* filePath, std::string& hash);

bool HexToString(uint8_t* byteArray, uint32_t size, std::string& str);
} // namespace analyzer