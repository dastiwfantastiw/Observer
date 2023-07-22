#pragma once
#include "config.h"

struct LdrData;
struct InjectData;

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* dllMain)(HMODULE, DWORD, InjectData* data);
typedef DWORD(WINAPI* pLoader)(LdrData* data);

struct InjectData
{
    CBinaryConfig* BinaryConfig;
    uint32_t BinaryConfigSize;
    LdrData* LdrData;
    pLoader Loader;
    uint32_t LoaderSize;
};