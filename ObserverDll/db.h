#pragma once
#include "observer_dll.h"

typedef std::function<void(uint32_t, uint32_t*, Registers*, void*, std::vector<std::string>&, DbFunction&, SyscallStatus&)> eventHandler;

#pragma pack(push, 1)
struct DbFunction
{
    std::string Name;
    uint32_t Hash;
    uint32_t Argc;
    config::Mode Mode;
    config::Type Types;
    uint8_t MaxPtr;
    uint32_t MinStrLen;
    uint32_t MaxStrLen;
    bool EventEnabled;
    eventHandler EventHandler;
};
#pragma pack(pop)

namespace db {
extern std::map<uint32_t, std::map<uint32_t, eventHandler>> dbEvents;

bool GetSyscallFromModule(IMAGE_DOS_HEADER* image,
                          std::map<uint32_t, DbFunction>& db,
                          config::ModuleData& moduleData,
                          std::map<uint32_t, config::FunctionData>& funcs);
IMAGE_DOS_HEADER* FindModule(uint32_t hash);
} // namespace db