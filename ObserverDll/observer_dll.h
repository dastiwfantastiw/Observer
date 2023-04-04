#pragma once
#include <map>

#include "../Observer/config.h"
#include "../Observer/inject.h"

#include "log.h"
#include "memory.h"
#include "migrate.h"

struct Registers
{
    uint32_t EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX;
};

enum SyscallStatus : uint32_t
{
    NotExecuted,
    Executed
};

enum GuardStatus : uint32_t
{
    DontSkip,
    Skip
};

typedef std::map<uint32_t, DbFunction> DbFuncs;

namespace observer_dll {

extern uint8_t OriginalBytes[7];
extern uint32_t Guard;
extern inject::ObserverDllData* InjectData;

extern DbFuncs* DbFunctions;

bool InstallHook();
void UninstallHook();

SyscallStatus WINAPI SyscallHandler(uint32_t id, uint32_t* args, Registers* regs, void* jmpAddress);
GuardStatus WINAPI ThreadGuard(uint32_t id);

bool InitFromConfig(HMODULE hModule, inject::ObserverDllData* injectData);
bool WINAPI ExecuteSystemCall(uint32_t id, uint16_t argc, uint32_t* args, Registers* regs, void* jump);

bool Migrate(HANDLE processHandle, HANDLE threadHandle);

bool EnableGuardForThread();
bool DisableGuardForThread();

void LogProcessInformation();

} // namespace observer_dll