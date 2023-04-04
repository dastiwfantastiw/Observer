#include "db.h"

#include <bitset>
#include <map>

namespace constants {
namespace memory {
extern const std::map<uint32_t, std::string>* allocFlags;
extern const std::map<uint32_t, std::string>* protectFlags;
} // namespace memory

namespace file {
extern const std::map<uint32_t, std::string>* fileAttribs;
extern const std::map<uint32_t, std::string>* fileShareAccesses;
extern const std::map<uint32_t, std::string>* fileCreateDispositions;
extern const std::map<uint32_t, std::string>* fileCreateOptions;
extern const std::map<uint32_t, std::string>* fileIOStatus;
} // namespace file

namespace key {
extern const std::map<uint32_t, std::string>* keyCreateDispositions;
extern const std::map<uint32_t, std::string>* keyCreateOptions;
extern const std::map<uint32_t, std::string>* keyTypes;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

extern const std::map<uint32_t, std::string>* keyValueInfoClass;
} // namespace key

namespace process {
extern const std::map<uint32_t, std::string>* processAccessMasks;
}

namespace thread {
extern const std::map<uint32_t, std::string>* threadAccessMasks;
}

} // namespace constants

void OnCreateUserProcess(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnOpenProcess(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);

void OnAllocateVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnProtectVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnReadVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnWriteVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnWow64ReadVirtualMemory64(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnWow64WriteVirtualMemory64(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);

void OnReadFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnWriteFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnCreateFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnOpenFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnDeviceIoControlFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);

void OnCreateKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnDeleteKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnDeleteValueKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnSetValueKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnQueryValueKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnEnumerateKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);

void OnGetContextThread(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);
void OnSetContextThread(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status);