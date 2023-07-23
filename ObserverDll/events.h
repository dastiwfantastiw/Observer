#pragma once
#include "config.h"
#include "defines.h"
#include "logger.h"

#include <functional>
#include <map>
#include <ntstatus.h>
#include <string>

typedef std::map<uint32_t, std::string> MapFlags;

class CDbFunction;
class CDbModule;

struct Registers
{
    uint32_t EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX;
};

enum SyscallStatus : uint32_t
{
    NotExecuted,
    Executed
};

class CEvent
{
public:
    CLogger& m_Logger;
    ProcModes m_procMode;

    virtual void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) = 0;

protected:
    CEvent(CLogger& logger, ProcModes procMode)
        : m_Logger(logger)
        , m_procMode(procMode){};
    virtual ~CEvent(){};
};

// Process
class OnCreateUserProcess: public CEvent
{
public:
    OnCreateUserProcess(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnOpenProcess: public CEvent
{
public:
    OnOpenProcess(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

// Memory
class OnAllocateVirtualMemory: public CEvent
{
public:
    OnAllocateVirtualMemory(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnWow64AllocateVirtualMemory64: public CEvent
{
public:
    OnWow64AllocateVirtualMemory64(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnProtectVirtualMemory: public CEvent
{
public:
    OnProtectVirtualMemory(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnWow64ProtectVirtualMemory64: public CEvent
{
public:
    OnWow64ProtectVirtualMemory64(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnReadVirtualMemory: public CEvent
{
public:
    OnReadVirtualMemory(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnWriteVirtualMemory: public CEvent
{
public:
    OnWriteVirtualMemory(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnWow64ReadVirtualMemory64: public CEvent
{
public:
    OnWow64ReadVirtualMemory64(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnWow64WriteVirtualMemory64: public CEvent
{
public:
    OnWow64WriteVirtualMemory64(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnFreeVirtualMemory: public CEvent
{
public:
    OnFreeVirtualMemory(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

// File
class OnReadFile: public CEvent
{
public:
    OnReadFile(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnWriteFile: public CEvent
{
public:
    OnWriteFile(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnCreateFile: public CEvent
{
public:
    OnCreateFile(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnOpenFile: public CEvent
{
public:
    OnOpenFile(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnDeviceIoControlFile: public CEvent
{
public:
    OnDeviceIoControlFile(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

// Key
class OnCreateKey: public CEvent
{
public:
    OnCreateKey(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnDeleteKey: public CEvent
{
public:
    OnDeleteKey(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnDeleteValueKey: public CEvent
{
public:
    OnDeleteValueKey(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnSetValueKey: public CEvent
{
public:
    OnSetValueKey(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnQueryValueKey: public CEvent
{
public:
    OnQueryValueKey(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnEnumerateKey: public CEvent
{
public:
    OnEnumerateKey(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

// Thread
class OnGetContextThread: public CEvent
{
public:
    OnGetContextThread(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnSetContextThread: public CEvent
{
public:
    OnSetContextThread(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnCreateThreadEx: public CEvent
{
public:
    OnCreateThreadEx(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

// Section
class OnCreateSection: public CEvent
{
public:
    OnCreateSection(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};

class OnMapViewOfSection: public CEvent
{
public:
    OnMapViewOfSection(CLogger& logger, ProcModes procMode)
        : CEvent(logger, procMode){};

    void Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status) override;
};