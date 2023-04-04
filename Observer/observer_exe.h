#pragma once
#include <cstdio>
#include <fstream>
#include <string>

#include "config.h"

namespace observer_exe {
class ObserverExe
{
private:
    std::string ProcessImagePath;
    std::string ProcessCmdLine;

    config::BinaryConfig* Config;

    struct DllInfo
    {
        std::string Path;
        IMAGE_DOS_HEADER* MapView;
        HANDLE MapHandle;
    } DllInfo;

    std::map<std::string, config::Type> ConfigTypes = {
        {"char", config::TypeCharArray},
        {"wchar", config::TypeWideCharArray},
        {"ansistring", config::TypeAnsiString},
        {"unicodestring", config::TypeUnicodeString},
        {"process", config::TypeProcessHandle},
        {"file", config::TypeFileHandle},
        {"key", config::TypeRegKeyHandle},
        {"thread", config::TypeThreadHandle},
        {"section", config::TypeSectionHandle},
        {"mutant", config::TypeMutantHandle},
        {"event", config::TypeEventHandle},
        {"handles", config::TypeAnyHandle},
        {"strings", config::TypeStrings}};

    std::map<std::string, config::Mode> ConfigModes = {
        {"before", config::Mode::ModeBefore},
        {"after", config::Mode::ModeAfter},
        {"both", config::Mode::ModeBoth},
    };

public:
    void GetProcessImagePath(const char* imagePath);
    void GetProcessCommandLine(const char* cmdline);
    bool GetDll(const char* dllPath);
    bool GetJson(const char* jsonPath);
    bool Execute(bool isDebug);
    bool SaveBinaryToFile(const char* filePath);
    bool ReadBinaryFromFile(const char* filePath);

    ObserverExe();

private:
    config::BinaryConfig* JsonToBinary(json& js);

    bool GetModuleInfo(const std::string& moduleName, json& js, std::vector<uint8_t>& vecMd);
    bool GetFuncsInfo(json::object_t& js, config::ModuleData& md, std::vector<uint8_t>& vecFd);
    void StringModeToBin(std::string& str, config::Mode& dest);
    void StringTypeToBin(json::array_t& js, config::Type& dest);
};
} // namespace observer_exe
