#include "events.h"
#include "analyzer.h"
#include "formatters.h"

#define READ_PTR(ptr) (*ptr)

#define FORMAT_PROCESS(pid, path) "Process: {{{:#x} ({:d}), \"{:s}\"}}", (uint32_t)pid, (uint32_t)pid, path
#define FORMAT_COMMANDLINE(str) "CommandLine: \"{:s}\"", str
#define FORMAT_TID(tid) "Tid: {:#x} ({:d})", (uint32_t)tid, (uint32_t)tid
#define FORMAT_BASE_ADDRESS(address) "BaseAddress: {:#010x}", (uint32_t)address)
#define FORMAT_SIZE(size) "Size: {:#010x} ({:d} bytes)", (uint32_t)size, (uint32_t)size)
#define FORMAT_BUFFER(buffer) "Buffer: {:#010x}", (uint32_t)buffer
#define FORMAT_BINARY(binary) "{}", binary
#define FORMAT_SIZE_READED(size) "SizeReaded: {:#010x} ({:d} bytes)", (uint32_t)size, (uint32_t)size
#define FORMAT_SIZE_WRITTEN(size) "SizeWritten: {:#010x} ({:d} bytes)", (uint32_t)size, (uint32_t)size
#define FORMAT_HANDLE(type, path) "{:s}: \"{:s}\"", type, path
#define FORMAT_IO_STATUS(status, str) "IOStatus: {{{:#010x}, \"{:s}\"}}", (uint32_t)status, str
#define FORMAT_SHARE_ACCESS(access, str) "ShareAccess: {{{:#010x}, \"{:s}\"}}", (uint32_t)access, str
#define FORMAT_VALUE_NAME(str) "ValueName: \"{:s}\"", str
#define FORMAT_THREAD_CONTEXT(context) "Context: {{{}}}", (CONTEXT)context

namespace constants {

namespace memory {
const std::map<uint32_t, std::string>* allocFlags = new std::map<uint32_t, std::string>{
    {MEM_COMMIT, "MEM_COMMIT"},
    {MEM_RESERVE, "MEM_RESERVE"},
    {MEM_RESET, "MEM_RESET"},
    {MEM_TOP_DOWN, "MEM_TOP_DOWN"},
    {MEM_WRITE_WATCH, "MEM_WRITE_WATCH"},
    {MEM_PHYSICAL, "MEM_PHYSICAL"},
    {MEM_ROTATE, "MEM_ROTATE"},
    {MEM_RESET_UNDO, "MEM_RESET_UNDO"},
    {MEM_LARGE_PAGES, "MEM_LARGE_PAGES"},
    {MEM_4MB_PAGES, "MEM_4MB_PAGES"},
    {MEM_LARGE_PAGES | MEM_PHYSICAL, "MEM_64K_PAGES"},
    {MEM_UNMAP_WITH_TRANSIENT_BOOST, "MEM_UNMAP_WITH_TRANSIENT_BOOST"},
    {MEM_DECOMMIT, "MEM_DECOMMIT"},
    {MEM_RELEASE, "MEM_RELEASE"},
    {MEM_FREE, "MEM_FREE"}};

const std::map<uint32_t, std::string>* protectFlags = new std::map<uint32_t, std::string>{
    {PAGE_NOACCESS, "PAGE_NOACCESS"},
    {PAGE_READONLY, "PAGE_READONLY"},
    {PAGE_READWRITE, "PAGE_READWRITE"},
    {PAGE_WRITECOPY, "PAGE_WRITECOPY"},
    {PAGE_EXECUTE, "PAGE_EXECUTE"},
    {PAGE_EXECUTE_READ, "PAGE_EXECUTE_READ"},
    {PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE"},
    {PAGE_EXECUTE_WRITECOPY, "PAGE_EXECUTE_WRITECOPY"},
    {PAGE_GUARD, "PAGE_GUARD"},
    {PAGE_NOCACHE, "PAGE_NOCACHE"}};
} // namespace memory

namespace file {
const std::map<uint32_t, std::string>* fileAttribs = new std::map<uint32_t, std::string>{
    {FILE_ATTRIBUTE_READONLY, "FILE_ATTRIBUTE_READONLY"},
    {FILE_ATTRIBUTE_HIDDEN, "FILE_ATTRIBUTE_HIDDEN"},
    {FILE_ATTRIBUTE_SYSTEM, "FILE_ATTRIBUTE_SYSTEM"},
    {FILE_ATTRIBUTE_DIRECTORY, "FILE_ATTRIBUTE_DIRECTORY"},
    {FILE_ATTRIBUTE_ARCHIVE, "FILE_ATTRIBUTE_ARCHIVE"},
    {FILE_ATTRIBUTE_DEVICE, "FILE_ATTRIBUTE_DEVICE"},
    {FILE_ATTRIBUTE_NORMAL, "FILE_ATTRIBUTE_NORMAL"},
    {FILE_ATTRIBUTE_TEMPORARY, "FILE_ATTRIBUTE_TEMPORARY"},
    {FILE_ATTRIBUTE_SPARSE_FILE, "FILE_ATTRIBUTE_SPARSE_FILE"},
    {FILE_ATTRIBUTE_REPARSE_POINT, "FILE_ATTRIBUTE_REPARSE_POINT"},
    {FILE_ATTRIBUTE_COMPRESSED, "FILE_ATTRIBUTE_COMPRESSED"},
    {FILE_ATTRIBUTE_OFFLINE, "FILE_ATTRIBUTE_OFFLINE"},
    {FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"},
    {FILE_ATTRIBUTE_ENCRYPTED, "FILE_ATTRIBUTE_ENCRYPTED"},
    {FILE_ATTRIBUTE_INTEGRITY_STREAM, "FILE_ATTRIBUTE_INTEGRITY_STREAM"},
    {FILE_ATTRIBUTE_VIRTUAL, "FILE_ATTRIBUTE_VIRTUAL"},
    {FILE_ATTRIBUTE_NO_SCRUB_DATA, "FILE_ATTRIBUTE_NO_SCRUB_DATA"},
    {FILE_ATTRIBUTE_EA, "FILE_ATTRIBUTE_EA"},
    {FILE_ATTRIBUTE_PINNED, "FILE_ATTRIBUTE_PINNED"},
    {FILE_ATTRIBUTE_UNPINNED, "FILE_ATTRIBUTE_UNPINNED"},
    {FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS"},
    {FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL, "FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL"}};

const std::map<uint32_t, std::string>* fileShareAccesses = new std::map<uint32_t, std::string>{
    {FILE_SHARE_READ, "FILE_SHARE_READ"},
    {FILE_SHARE_WRITE, "FILE_SHARE_WRITE"},
    {FILE_SHARE_DELETE, "FILE_SHARE_DELETE"}};

const std::map<uint32_t, std::string>* fileCreateDispositions = new std::map<uint32_t, std::string>{
    {FILE_SUPERSEDE, "FILE_SUPERSEDE"},
    {FILE_OPEN, "FILE_OPEN"},
    {FILE_CREATE, "FILE_CREATE"},
    {FILE_OPEN_IF, "FILE_OPEN_IF"},
    {FILE_OVERWRITE, "FILE_OVERWRITE"},
    {FILE_MAXIMUM_DISPOSITION, "FILE_MAXIMUM_DISPOSITION"}};

const std::map<uint32_t, std::string>* fileCreateOptions = new std::map<uint32_t, std::string>{
    {FILE_DIRECTORY_FILE, "FILE_DIRECTORY_FILE"},
    {FILE_WRITE_THROUGH, "FILE_WRITE_THROUGH"},
    {FILE_SEQUENTIAL_ONLY, "FILE_SEQUENTIAL_ONLY"},
    {FILE_NO_INTERMEDIATE_BUFFERING, "FILE_NO_INTERMEDIATE_BUFFERING"},
    {FILE_SYNCHRONOUS_IO_ALERT, "FILE_SYNCHRONOUS_IO_ALERT"},
    {FILE_SYNCHRONOUS_IO_NONALERT, "FILE_SYNCHRONOUS_IO_NONALERT"},
    {FILE_NON_DIRECTORY_FILE, "FILE_NON_DIRECTORY_FILE"},
    {FILE_CREATE_TREE_CONNECTION, "FILE_CREATE_TREE_CONNECTION"},
    {FILE_COMPLETE_IF_OPLOCKED, "FILE_COMPLETE_IF_OPLOCKED"},
    {FILE_NO_EA_KNOWLEDGE, "FILE_NO_EA_KNOWLEDGE"},
    {FILE_OPEN_REMOTE_INSTANCE, "FILE_OPEN_REMOTE_INSTANCE"},
    {FILE_RANDOM_ACCESS, "FILE_RANDOM_ACCESS"},
    {FILE_DELETE_ON_CLOSE, "FILE_DELETE_ON_CLOSE"},
    {FILE_OPEN_BY_FILE_ID, "FILE_OPEN_BY_FILE_ID"},
    {FILE_OPEN_FOR_BACKUP_INTENT, "FILE_OPEN_FOR_BACKUP_INTENT"},
    {FILE_NO_COMPRESSION, "FILE_NO_COMPRESSION"},
    {FILE_OPEN_REQUIRING_OPLOCK, "FILE_OPEN_REQUIRING_OPLOCK"},
    {FILE_RESERVE_OPFILTER, "FILE_RESERVE_OPFILTER"},
    {FILE_OPEN_REPARSE_POINT, "FILE_OPEN_REPARSE_POINT"},
    {FILE_OPEN_NO_RECALL, "FILE_OPEN_NO_RECALL"},
    {FILE_OPEN_FOR_FREE_SPACE_QUERY, "FILE_OPEN_FOR_FREE_SPACE_QUERY"},
    {FILE_VALID_OPTION_FLAGS, "FILE_VALID_OPTION_FLAGS"},
    {FILE_VALID_PIPE_OPTION_FLAGS, "FILE_VALID_PIPE_OPTION_FLAGS"},
    {FILE_VALID_MAILSLOT_OPTION_FLAGS, "FILE_VALID_MAILSLOT_OPTION_FLAGS"},
    {FILE_VALID_SET_FLAGS, "FILE_VALID_SET_FLAGS"},
};

const std::map<uint32_t, std::string>* fileIOStatus = new std::map<uint32_t, std::string>{
    {FILE_SUPERSEDED, "FILE_SUPERSEDED"},
    {FILE_OPENED, "FILE_OPENED"},
    {FILE_CREATED, "FILE_CREATED"},
    {FILE_OVERWRITTEN, "FILE_OVERWRITTEN"},
    {FILE_EXISTS, "FILE_EXISTS"},
    {FILE_DOES_NOT_EXIST, "FILE_DOES_NOT_EXIST"}};
} // namespace file

namespace key {
const std::map<uint32_t, std::string>* keyCreateDispositions = new std::map<uint32_t, std::string>{
    {REG_CREATED_NEW_KEY, "REG_CREATED_NEW_KEY"},
    {REG_OPENED_EXISTING_KEY, "REG_OPENED_EXISTING_KEY"}};

const std::map<uint32_t, std::string>* keyCreateOptions = new std::map<uint32_t, std::string>{
    {REG_OPTION_RESERVED, "REG_OPTION_RESERVED"},
    {REG_OPTION_NON_VOLATILE, "REG_OPTION_NON_VOLATILE"},
    {REG_OPTION_CREATE_LINK, "REG_OPTION_CREATE_LINK"},
    {REG_OPTION_BACKUP_RESTORE, "REG_OPTION_BACKUP_RESTORE"},
    {REG_OPTION_OPEN_LINK, "REG_OPTION_OPEN_LINK"},
    {REG_OPTION_DONT_VIRTUALIZE, "REG_OPTION_DONT_VIRTUALIZE"}};

const std::map<uint32_t, std::string>* keyTypes = new std::map<uint32_t, std::string>{
    {REG_NONE, "REG_NONE"},
    {REG_SZ, "REG_SZ"},
    {REG_EXPAND_SZ, "REG_EXPAND_SZ"},
    {REG_BINARY, "REG_BINARY"},
    {REG_DWORD, "REG_DWORD"},
    {REG_DWORD_BIG_ENDIAN, "REG_DWORD_BIG_ENDIAN"},
    {REG_LINK, "REG_LINK"},
    {REG_MULTI_SZ, "REG_MULTI_SZ"},
    {REG_RESOURCE_LIST, "REG_RESOURCE_LIST"},
    {REG_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR"},
    {REG_RESOURCE_REQUIREMENTS_LIST, "REG_RESOURCE_REQUIREMENTS_LIST"},
    {REG_QWORD, "REG_QWORD"}};

const std::map<uint32_t, std::string>* keyValueInfoClass = new std::map<uint32_t, std::string>{
    {KeyValueBasicInformation, "KeyValueBasicInformation"},
    {KeyValueFullInformation, "KeyValueFullInformation"},
    {KeyValuePartialInformation, "KeyValuePartialInformation"},
    {KeyValueFullInformationAlign64, "KeyValueFullInformationAlign64"},
    {KeyValuePartialInformationAlign64, "KeyValuePartialInformationAlign64"},
    {KeyValueLayerInformation, "KeyValueLayerInformation"},
    {MaxKeyValueInfoClass, "MaxKeyValueInfoClass"}};
} // namespace key

namespace process {
const std::map<uint32_t, std::string>* processAccessMasks = new std::map<uint32_t, std::string>{
    {PROCESS_TERMINATE, "PROCESS_TERMINATE"},
    {PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"},
    {PROCESS_SET_SESSIONID, "PROCESS_SET_SESSIONID"},
    {PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"},
    {PROCESS_VM_READ, "PROCESS_VM_READ"},
    {PROCESS_VM_WRITE, "PROCESS_VM_WRITE"},
    {PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"},
    {PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS"},
    {PROCESS_SET_QUOTA, "PROCESS_SET_QUOTA"},
    {PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION"},
    {PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION"},
    {PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME"},
    {PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION"},
    {PROCESS_SET_LIMITED_INFORMATION, "PROCESS_SET_LIMITED_INFORMATION"}};
}

namespace thread {
const std::map<uint32_t, std::string>* threadAccessMasks = new std::map<uint32_t, std::string>{
    {THREAD_TERMINATE, "THREAD_TERMINATE"},
    {THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME"},
    {THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT"},
    {THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION"},
    {THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION"},
    {THREAD_SET_THREAD_TOKEN, "THREAD_SET_THREAD_TOKEN"},
    {THREAD_IMPERSONATE, "THREAD_IMPERSONATE"},
    {THREAD_DIRECT_IMPERSONATION, "THREAD_DIRECT_IMPERSONATION"},
    {THREAD_SET_LIMITED_INFORMATION, "THREAD_SET_LIMITED_INFORMATION"},
    {THREAD_QUERY_LIMITED_INFORMATION, "THREAD_QUERY_LIMITED_INFORMATION"},
    {THREAD_RESUME, "THREAD_RESUME"}};
}

} // namespace constants

//https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1219
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001                    // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002             // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004              // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008       // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010                  // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020        // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040            // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080               // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100          // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200                    // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400              // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS 0x00000800              // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000              // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000                // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000 //
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000            // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000                 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000    // NtCreateProcessEx & NtCreateUserProcess

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001      // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002    // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004    // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010         // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020      // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080        // ?

void OnCreateUserProcess(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    typedef struct _PS_ATTRIBUTE
    {
        ULONG Attribute;
        SIZE_T Size;
        union
        {
            ULONG Value;
            PVOID ValuePtr;
        };
        PSIZE_T ReturnLength;
    } PS_ATTRIBUTE, *PPS_ATTRIBUTE;

    typedef struct _PS_ATTRIBUTE_LIST
    {
        SIZE_T TotalLength;
        PS_ATTRIBUTE Attributes[1];
    } PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

    typedef enum _PS_CREATE_STATE
    {
        PsCreateInitialState,
        PsCreateFailOnFileOpen,
        PsCreateFailOnSectionCreate,
        PsCreateFailExeFormat,
        PsCreateFailMachineMismatch,
        PsCreateFailExeName, // Debugger specified
        PsCreateSuccess,
        PsCreateMaximumStates
    } PS_CREATE_STATE;

    typedef struct _PS_CREATE_INFO
    {
        SIZE_T Size;
        PS_CREATE_STATE State;
        union
        {
            // PsCreateInitialState
            struct
            {
                union
                {
                    ULONG InitFlags;
                    struct
                    {
                        UCHAR WriteOutputOnExit : 1;
                        UCHAR DetectManifest : 1;
                        UCHAR IFEOSkipDebugger : 1;
                        UCHAR IFEODoNotPropagateKeyState : 1;
                        UCHAR SpareBits1 : 4;
                        UCHAR SpareBits2 : 8;
                        USHORT ProhibitedImageCharacteristics : 16;
                    };
                };
                ACCESS_MASK AdditionalFileAccess;
            } InitState;

            // PsCreateFailOnSectionCreate
            struct
            {
                HANDLE FileHandle;
            } FailSection;

            // PsCreateFailExeFormat
            struct
            {
                USHORT DllCharacteristics;
            } ExeFormat;

            // PsCreateFailExeName
            struct
            {
                HANDLE IFEOKey;
            } ExeName;

            // PsCreateSuccess
            struct
            {
                union
                {
                    ULONG OutputFlags;
                    struct
                    {
                        UCHAR ProtectedProcess : 1;
                        UCHAR AddressSpaceOverride : 1;
                        UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                        UCHAR ManifestDetected : 1;
                        UCHAR ProtectedProcessLight : 1;
                        UCHAR SpareBits1 : 3;
                        UCHAR SpareBits2 : 8;
                        USHORT SpareBits3 : 16;
                    };
                };
                HANDLE FileHandle;
                HANDLE SectionHandle;
                ULONGLONG UserProcessParametersNative;
                ULONG UserProcessParametersWow64;
                ULONG CurrentParameterFlags;
                ULONGLONG PebAddressNative;
                ULONG PebAddressWow64;
                ULONGLONG ManifestAddress;
                ULONG ManifestSize;
            } SuccessState;
        };
    } PS_CREATE_INFO, *PPS_CREATE_INFO;

    typedef NTSTATUS(NTAPI *
                     NtCreateUserProcess)(
        OUT PHANDLE ProcessHandle,
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK ProcessDesiredAccess,
        IN ACCESS_MASK ThreadDesiredAccess,
        IN OPTIONAL POBJECT_ATTRIBUTES ProcessObjectAttributes,
        IN OPTIONAL POBJECT_ATTRIBUTES ThreadObjectAttributes,
        IN ULONG ProcessFlags,                                       // PROCESS_CREATE_FLAGS_*
        IN ULONG ThreadFlags,                                        // THREAD_CREATE_FLAGS_*
        IN OPTIONAL RTL_USER_PROCESS_PARAMETERS * ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
        IN OUT PPS_CREATE_INFO CreateInfo,
        IN OPTIONAL PPS_ATTRIBUTE_LIST AttributeList);

    PHANDLE ProcessHandle = (PHANDLE)args[0];
    PHANDLE ThreadHandle = (PHANDLE)args[1];
    ACCESS_MASK ProcessFlags = args[6];
    ACCESS_MASK ThreadFlags = args[7];
    RTL_USER_PROCESS_PARAMETERS* ProcessParameters = (RTL_USER_PROCESS_PARAMETERS*)args[8];

    const std::map<uint32_t, std::string> constProcessCreateFlags = {
        {PROCESS_CREATE_FLAGS_BREAKAWAY, "CREATE_FLAGS_BREAKAWAY"},
        {PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT, "CREATE_FLAGS_NO_DEBUG_INHERIT"},
        {PROCESS_CREATE_FLAGS_INHERIT_HANDLES, "CREATE_FLAGS_INHERIT_HANDLES"},
        {PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE, "CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE"},
        {PROCESS_CREATE_FLAGS_LARGE_PAGES, "CREATE_FLAGS_LARGE_PAGES"},
        {PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL, "CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL"},
        {PROCESS_CREATE_FLAGS_PROTECTED_PROCESS, "CREATE_FLAGS_PROTECTED_PROCESS"},
        {PROCESS_CREATE_FLAGS_CREATE_SESSION, "CREATE_FLAGS_CREATE_SESSION"},
        {PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT, "CREATE_FLAGS_INHERIT_FROM_PARENT"},
        {PROCESS_CREATE_FLAGS_SUSPENDED, "CREATE_FLAGS_SUSPENDED"},
        {PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY, "CREATE_FLAGS_FORCE_BREAKAWAY"},
        {PROCESS_CREATE_FLAGS_MINIMAL_PROCESS, "CREATE_FLAGS_MINIMAL_PROCESS"},
        {PROCESS_CREATE_FLAGS_RELEASE_SECTION, "CREATE_FLAGS_RELEASE_SECTION"},
        {PROCESS_CREATE_FLAGS_CLONE_MINIMAL, "CREATE_FLAGS_CLONE_MINIMAL"},
        {PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT, "CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT"},
        {PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS, "CREATE_FLAGS_AUXILIARY_PROCESS"},
        {PROCESS_CREATE_FLAGS_CREATE_STORE, "CREATE_FLAGS_CREATE_STORE"},
        {PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT, "CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT"}};

    const std::map<uint32_t, std::string> constThreadCreateFlags = {
        {THREAD_CREATE_FLAGS_CREATE_SUSPENDED, "CREATE_FLAGS_CREATE_SUSPENDED"},
        {THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH, "CREATE_FLAGS_SKIP_THREAD_ATTACH"},
        {THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, "CREATE_FLAGS_HIDE_FROM_DEBUGGER"},
        {THREAD_CREATE_FLAGS_LOADER_WORKER, "CREATE_FLAGS_LOADER_WORKER"},
        {THREAD_CREATE_FLAGS_SKIP_LOADER_INIT, "CREATE_FLAGS_SKIP_LOADER_INIT"},
        {THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE, "CREATE_FLAGS_BYPASS_PROCESS_FREEZE"},
        {THREAD_CREATE_FLAGS_INITIAL_THREAD, "CREATE_FLAGS_INITIAL_THREAD"}};

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (ProcessHandle && ThreadHandle)
            {
                uint32_t pid = GetProcessId(READ_PTR(ProcessHandle));
                uint32_t tid = GetThreadId(READ_PTR(ThreadHandle));

                std::string imagePath, commandLine, strProcessFlags, strThreadFlags;

                if (ProcessParameters)
                {
                    imagePath.reserve(ProcessParameters->ImagePathName.Length);
                    commandLine.reserve(ProcessParameters->CommandLine.Length);

                    analyzer::UnicodeToAnsi(ProcessParameters->ImagePathName.Buffer, imagePath.data(), ProcessParameters->ImagePathName.Length, NULL);
                    analyzer::UnicodeToAnsi(ProcessParameters->CommandLine.Buffer, commandLine.data(), ProcessParameters->CommandLine.Length, NULL);
                }

                analyzer::GetStringFromConstants(ProcessFlags, &constProcessCreateFlags, strProcessFlags);
                analyzer::GetStringFromConstants(ThreadFlags, &constThreadCreateFlags, strThreadFlags);

                std::vector<std::string> args;

                args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                args.push_back(std::format(FORMAT_COMMANDLINE(commandLine.c_str())));
                args.push_back(std::format(FORMAT_TID(tid)));
                args.push_back(std::format("CreateProcessFlags: {{{:#010x}, \"{:s}\"}}", ProcessFlags, strProcessFlags.c_str()));
                args.push_back(std::format("CreateThreadFlags: {{{:#010x}, \"{:s}\"}}", ThreadFlags, strThreadFlags.c_str()));

                logger::LogEventWithTime(__FUNCTION__, args, NULL);

                observer_dll::Migrate(READ_PTR(ProcessHandle), READ_PTR(ThreadHandle));
            }
        }
    }
}

void OnOpenProcess(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    OUT PHANDLE ProcessHandle = (PHANDLE)args[0];
    IN ACCESS_MASK AccessMask = args[1];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (ProcessHandle)
            {
                uint32_t pid = GetProcessId(*ProcessHandle);

                std::string imagePath, strAccessMask;

                analyzer::GetStringFromConstants(AccessMask, constants::process::processAccessMasks, strAccessMask);

                if (analyzer::QueryProcessImage(*ProcessHandle, imagePath))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                    args.push_back(std::format("Access: {{{:#010x}, \"{:s}\"}}", AccessMask, strAccessMask.c_str()));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnAllocateVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ProcessHandle = (HANDLE)args[0];
    IN OUT PVOID* BaseAddress = (PVOID*)args[1];
    IN OUT SIZE_T* RegionSize = (SIZE_T*)args[3];
    IN ULONG Allocation = args[4];
    IN ULONG Protect = args[5];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (BaseAddress && RegionSize)
            {
                uint32_t pid = GetProcessId(ProcessHandle);

                std::string imagePath, strAllocType, strProtectType;

                analyzer::GetStringFromConstants(Allocation, constants::memory::allocFlags, strAllocType);
                analyzer::GetStringFromConstants(Protect, constants::memory::protectFlags, strProtectType);

                if (analyzer::QueryProcessImage(ProcessHandle, imagePath))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                    args.push_back(std::format(FORMAT_BASE_ADDRESS(READ_PTR((uint32_t*)BaseAddress)));
                    args.push_back(std::format(FORMAT_SIZE(READ_PTR(RegionSize)));
                    args.push_back(std::format("AllocationType: {{{:#010x}, \"{:s}\"}}", (uint32_t)Allocation, strAllocType.c_str()));
                    args.push_back(std::format("ProtectionType: {{{:#010x}, \"{:s}\"}}", (uint32_t)Protect, strProtectType.c_str()));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnProtectVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ProcessHandle = (HANDLE)args[0];
    IN OUT PVOID* BaseAddress = (PVOID*)args[1];
    IN OUT PULONG NumberOfBytesToProtect = (PULONG)args[2];
    IN ULONG NewAccessProtection = args[3];
    OUT PULONG OldAccessProtection = (PULONG)args[4];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (BaseAddress && NumberOfBytesToProtect && OldAccessProtection)
            {
                uint32_t pid = GetProcessId(ProcessHandle);

                std::string strNewProtect, strOldProtect, imagePath;

                analyzer::GetStringFromConstants(NewAccessProtection, constants::memory::protectFlags, strNewProtect);
                analyzer::GetStringFromConstants(READ_PTR(OldAccessProtection), constants::memory::protectFlags, strOldProtect);

                if (analyzer::QueryProcessImage(ProcessHandle, imagePath))
                {
                    std::vector<std::string> args;

                    std::vector<uint8_t> binary;

                    bool isExecutable = NewAccessProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

                    if (isExecutable)
                    {
                        binary.insert(binary.begin(), *(uint8_t**)BaseAddress, *(uint8_t**)BaseAddress + *NumberOfBytesToProtect);
                    }

                    args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                    args.push_back(std::format(FORMAT_BASE_ADDRESS(READ_PTR((uint32_t*)BaseAddress)));
                    args.push_back(std::format(FORMAT_SIZE(READ_PTR(NumberOfBytesToProtect)));
                    args.push_back(std::format("NewProtection: {{{:#010x}, \"{:s}\"}}", (uint32_t)NewAccessProtection, strNewProtect.c_str()));
                    args.push_back(std::format("OldProtection: {{{:#010x}, \"{:s}\"}}", READ_PTR(OldAccessProtection), strOldProtect.c_str()));

                    if (isExecutable)
                    {
                        args.push_back(std::format(FORMAT_BINARY(binary)));
                    }

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnReadVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ProcessHandle = (HANDLE)args[0];
    IN PVOID BaseAddress = (PVOID)args[1];
    OUT PVOID Buffer = (PVOID)args[2];
    IN ULONG NumberOfBytesToRead = args[3];
    OUT OPTIONAL PULONG NumberOfBytesReaded = (PULONG)args[4];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (BaseAddress && NumberOfBytesReaded)
            {
                uint32_t pid = GetProcessId(ProcessHandle);
                uint32_t sizeReaded = READ_PTR(NumberOfBytesReaded);

                std::string imagePath;

                std::vector<uint8_t> binary((uint8_t*)Buffer, (uint8_t*)Buffer + sizeReaded);

                if (analyzer::QueryProcessImage(ProcessHandle, imagePath))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                    args.push_back(std::format(FORMAT_BASE_ADDRESS(BaseAddress));
                    args.push_back(std::format(FORMAT_BUFFER(Buffer)));
                    args.push_back(std::format("SizeToRead: {:#010x} ({:d} bytes)", (uint32_t)NumberOfBytesToRead, (uint32_t)NumberOfBytesToRead));
                    args.push_back(std::format(FORMAT_SIZE_READED(sizeReaded)));
                    args.push_back(std::format(FORMAT_BINARY(binary)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnWriteVirtualMemory(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ProcessHandle = (HANDLE)args[0];
    IN PVOID BaseAddress = (PVOID)args[1];
    IN PVOID Buffer = (PVOID)args[2];
    IN ULONG NumberOfBytesToWrite = args[3];
    OUT OPTIONAL PULONG NumberOfBytesWritten = (PULONG)args[4];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (BaseAddress && NumberOfBytesWritten)
            {
                uint32_t pid = GetProcessId(ProcessHandle);
                uint32_t sizeWritten = READ_PTR(NumberOfBytesWritten);

                std::string imagePath;

                std::vector<uint8_t> binary((uint8_t*)Buffer, (uint8_t*)Buffer + sizeWritten);

                if (analyzer::QueryProcessImage(ProcessHandle, imagePath))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                    args.push_back(std::format(FORMAT_BASE_ADDRESS(BaseAddress));
                    args.push_back(std::format(FORMAT_BUFFER(Buffer)));
                    args.push_back(std::format("SizeToWrite: {:#010x} ({:d} bytes)", (uint32_t)NumberOfBytesToWrite, (uint32_t)NumberOfBytesToWrite));
                    args.push_back(std::format(FORMAT_SIZE_WRITTEN(sizeWritten)));
                    args.push_back(std::format(FORMAT_BINARY(binary)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnWow64ReadVirtualMemory64(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ProcessHandle = (HANDLE)args[0];
    IN OPTIONAL PVOID AddressLow = (PVOID)args[1];
    IN OPTIONAL PVOID AddressHigh = (PVOID)args[2];
    OUT PVOID Buffer = (PVOID)args[3];
    IN LONG BufferSizeLow = (ULONG)args[4];
    IN ULONG BufferSizeHigh = (ULONG)args[5];
    OUT OPTIONAL PULONGLONG BytesRead = (PULONGLONG)args[6];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (AddressLow && AddressHigh && Buffer && BytesRead)
            {
                uint32_t pid = GetProcessId(ProcessHandle);
                uint32_t sizeReaded = READ_PTR(BytesRead & 0xFFFFFFFF);

                std::string imagePath;

                std::vector<uint8_t> binary((uint8_t*)Buffer, (uint8_t*)Buffer + sizeReaded);

                if (analyzer::QueryProcessImage(ProcessHandle, imagePath))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                    args.push_back(std::format("AddressLow: {:#010x}", (uint32_t)AddressLow));
                    args.push_back(std::format("AddressHigh: {:#010x}", (uint32_t)AddressHigh));
                    args.push_back(std::format(FORMAT_BUFFER(Buffer)));
                    args.push_back(std::format(FORMAT_SIZE_READED(sizeReaded)));
                    args.push_back(std::format(FORMAT_BINARY(binary)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnWow64WriteVirtualMemory64(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ProcessHandle = (HANDLE)args[0];
    IN OPTIONAL PVOID AddressLow = (PVOID)args[1];
    IN OPTIONAL PVOID AddressHigh = (PVOID)args[2];
    OUT PVOID Buffer = (PVOID)args[3];
    IN ULONG BufferSizeLow = (ULONG)args[4];
    IN ULONG BufferSizeHigh = (ULONG)args[5];
    OUT OPTIONAL PULONGLONG BytesWritten = (PULONGLONG)args[6];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (AddressLow && AddressHigh && Buffer && BytesWritten)
            {
                uint32_t pid = GetProcessId(ProcessHandle);
                uint32_t sizeWritten = READ_PTR(BytesWritten & 0xFFFFFFFF);

                std::string imagePath;

                std::vector<uint8_t> binary((uint8_t*)Buffer, (uint8_t*)Buffer + sizeWritten);

                if (analyzer::QueryProcessImage(ProcessHandle, imagePath))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_PROCESS(pid, imagePath.c_str())));
                    args.push_back(std::format("AddressLow: {:#010x}", (uint32_t)AddressLow));
                    args.push_back(std::format("AddressHigh: {:#010x}", (uint32_t)AddressHigh));
                    args.push_back(std::format(FORMAT_BUFFER(Buffer)));
                    args.push_back(std::format(FORMAT_SIZE_WRITTEN(sizeWritten)));
                    args.push_back(std::format(FORMAT_BINARY(binary)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnReadFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE FileHandle = (HANDLE)args[0];
    OUT PVOID Buffer = (PVOID)args[5];
    IN ULONG Length = args[6];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (Buffer)
            {
                std::vector<uint8_t> binary((uint8_t*)Buffer, (uint8_t*)Buffer + Length);

                std::string type, name;

                if (analyzer::QueryNameObject(FileHandle, name) && analyzer::QueryTypeObject(FileHandle, type))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                    args.push_back(std::format(FORMAT_BUFFER(Buffer)));
                    args.push_back(std::format(FORMAT_SIZE(Length));
                    args.push_back(std::format(FORMAT_BINARY(binary)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnWriteFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE FileHandle = (HANDLE)args[0];
    OUT PVOID Buffer = (PVOID)args[5];
    IN ULONG Length = args[6];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (Buffer)
            {
                std::vector<uint8_t> binary((uint8_t*)Buffer, (uint8_t*)Buffer + Length);

                std::string type, name;

                if (analyzer::QueryNameObject(FileHandle, name) && analyzer::QueryTypeObject(FileHandle, type))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                    args.push_back(std::format(FORMAT_BUFFER(Buffer)));
                    args.push_back(std::format(FORMAT_SIZE(Length));
                    args.push_back(std::format(FORMAT_BINARY(binary)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnCreateFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    OUT PHANDLE FileHandle = (PHANDLE)args[0];
    OUT PIO_STATUS_BLOCK IoStatusBlock = (PIO_STATUS_BLOCK)args[3];
    IN ULONG FileAttributes = args[5];
    IN ULONG ShareAccess = args[6];
    IN ULONG CreateDisposition = args[7];
    IN ULONG CreateOptions = args[8];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (FileHandle && IoStatusBlock)
            {
                std::string type, name;

                if (analyzer::QueryNameObject(READ_PTR(FileHandle), name) && analyzer::QueryTypeObject(READ_PTR(FileHandle), type))
                {
                    std::vector<std::string> args;

                    std::string strFileAttribs, strShareAccess, strCreateDisposition, strCreateOptions, strIOStatus;

                    analyzer::GetStringFromConstants((uint32_t)FileAttributes, constants::file::fileAttribs, strFileAttribs);
                    analyzer::GetStringFromConstants((uint32_t)ShareAccess, constants::file::fileShareAccesses, strShareAccess);
                    analyzer::GetStringFromConstants((uint32_t)CreateDisposition, constants::file::fileCreateDispositions, strCreateDisposition);
                    analyzer::GetStringFromConstants((uint32_t)CreateOptions, constants::file::fileCreateOptions, strCreateOptions);
                    analyzer::GetStringFromConstants((uint32_t)IoStatusBlock->Status, constants::file::fileIOStatus, strIOStatus);

                    args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                    args.push_back(std::format("FileAttributes: {{{:#010x}, \"{:s}\"}}", (uint32_t)FileAttributes, strFileAttribs.c_str()));
                    args.push_back(std::format(FORMAT_SHARE_ACCESS((uint32_t)ShareAccess, strShareAccess.c_str())));
                    args.push_back(std::format("CreateDisposition: {{{:#010x}, \"{:s}\"}}", (uint32_t)CreateDisposition, strCreateDisposition.c_str()));
                    args.push_back(std::format("CreateOptions: {{{:#010x}, \"{:s}\"}}", (uint32_t)CreateOptions, strCreateOptions.c_str()));
                    args.push_back(std::format(FORMAT_IO_STATUS(IoStatusBlock->Status, strIOStatus.c_str())));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnOpenFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    OUT PHANDLE FileHandle = (PHANDLE)args[0];
    OUT PIO_STATUS_BLOCK IoStatusBlock = (PIO_STATUS_BLOCK)args[3];
    IN ULONG ShareAccess = args[4];
    IN ULONG OpenOptions = args[5];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (FileHandle && IoStatusBlock)
            {
                std::string type, name, strShareAccess, strOpenOptions, strIOStatus;

                analyzer::GetStringFromConstants((uint32_t)ShareAccess, constants::file::fileShareAccesses, strShareAccess);
                analyzer::GetStringFromConstants((uint32_t)OpenOptions, constants::file::fileCreateOptions, strOpenOptions);
                analyzer::GetStringFromConstants((uint32_t)IoStatusBlock->Status, constants::file::fileIOStatus, strIOStatus);

                if (analyzer::QueryNameObject(*FileHandle, name) && analyzer::QueryTypeObject(*FileHandle, type))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                    args.push_back(std::format(FORMAT_SHARE_ACCESS((uint32_t)ShareAccess, strShareAccess.c_str())));
                    args.push_back(std::format("OpenOptions: {{{:#010x}, \"{:s}\"}}", (uint32_t)OpenOptions, strOpenOptions.c_str()));
                    args.push_back(std::format(FORMAT_IO_STATUS(IoStatusBlock->Status, strIOStatus.c_str())));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnDeviceIoControlFile(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE FileHandle = (HANDLE)args[0];
    OUT PIO_STATUS_BLOCK IoStatusBlock = (PIO_STATUS_BLOCK)args[4];
    IN OPTIONAL PVOID InputBuffer = (PVOID)args[6];
    IN ULONG InputBufferLength = args[7];
    OUT OPTIONAL PVOID OutputBuffer = (PVOID)args[8];
    IN ULONG OutputBufferLength = args[9];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (FileHandle && IoStatusBlock && InputBuffer && OutputBuffer)
            {
                std::string type, name, strIOStatus;

                std::vector<uint8_t> binaryInput((uint8_t*)InputBuffer, (uint8_t*)InputBuffer + InputBufferLength);
                std::vector<uint8_t> binaryOutput((uint8_t*)OutputBuffer, (uint8_t*)OutputBuffer + OutputBufferLength);

                analyzer::GetStringFromConstants((uint32_t)IoStatusBlock->Status, constants::file::fileIOStatus, strIOStatus);

                if (analyzer::QueryNameObject(FileHandle, name) && analyzer::QueryTypeObject(FileHandle, type))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                    args.push_back(std::format(FORMAT_IO_STATUS(IoStatusBlock->Status, strIOStatus.c_str())));
                    args.push_back(std::format("InputBuffer: {:#010x}", (uint32_t)InputBuffer));
                    args.push_back(std::format("InputSize: {:#010x} ({:d} bytes)", InputBufferLength, InputBufferLength));
                    args.push_back(std::format(FORMAT_BINARY(binaryInput)));
                    args.push_back(std::format("OutputBuffer: {:#010x}", (uint32_t)OutputBuffer));
                    args.push_back(std::format("OutputSize: {:#010x} ({:d} bytes)", OutputBufferLength, OutputBufferLength));
                    args.push_back(std::format(FORMAT_BINARY(binaryOutput)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnCreateKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    OUT PHANDLE KeyHandle = (PHANDLE)args[0];
    IN ULONG CreateOptions = args[5];
    OUT OPTIONAL PULONG Disposition = (PULONG)args[6];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (KeyHandle && Disposition)
            {
                std::string type, name, strCreateOptions, strDisposition;

                analyzer::GetStringFromConstants((uint32_t)CreateOptions, constants::key::keyCreateOptions, strCreateOptions);
                analyzer::GetStringFromConstants(READ_PTR(Disposition), constants::key::keyCreateDispositions, strDisposition);

                if (analyzer::QueryTypeObject(READ_PTR(KeyHandle), type) && analyzer::QueryNameObject(READ_PTR(KeyHandle), name))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                    args.push_back(std::format("CreateOptions: {{{:#010x}, \"{:s}\"}}", (uint32_t)CreateOptions, strCreateOptions.c_str()));
                    args.push_back(std::format("CreateDisposition: {{{:#010x}, \"{:s}\"}}", READ_PTR(Disposition), strDisposition.c_str()));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnDeleteKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE KeyHandle = (HANDLE)args[0];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            std::string type, name;

            if (analyzer::QueryTypeObject(KeyHandle, type) && analyzer::QueryNameObject(KeyHandle, name))
            {
                std::vector<std::string> args;

                args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));

                logger::LogEventWithTime(__FUNCTION__, args, NULL);
            }
        }
    }
}

void OnDeleteValueKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE KeyHandle = (HANDLE)args[0];
    IN PUNICODE_STRING ValueName = (PUNICODE_STRING)args[1];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (ValueName)
            {
                std::string type, name, value;

                if (analyzer::QueryTypeObject(KeyHandle, type) && analyzer::QueryNameObject(KeyHandle, name))
                {
                    value.reserve(ValueName->Length);

                    if (analyzer::UnicodeToAnsi(ValueName->Buffer, value.data(), ValueName->Length, NULL))
                    {
                        std::vector<std::string> args;

                        args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                        args.push_back(std::format(FORMAT_VALUE_NAME(value.c_str())));

                        logger::LogEventWithTime(__FUNCTION__, args, NULL);
                    }
                }
            }
        }
    }
}

void OnSetValueKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE KeyHandle = (HANDLE)args[0];
    IN PUNICODE_STRING ValueName = (PUNICODE_STRING)args[1];
    IN ULONG Type = args[3];
    IN PVOID Data = (PVOID)args[4];
    IN ULONG DataSize = args[5];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (ValueName && Data)
            {
                std::string type, name, strType, value;

                std::vector<uint8_t> binary((uint8_t*)Data, (uint8_t*)Data + DataSize);

                analyzer::GetStringFromConstants(Type, constants::key::keyTypes, strType);

                if (analyzer::QueryTypeObject(KeyHandle, type) && analyzer::QueryNameObject(KeyHandle, name))
                {
                    value.reserve(ValueName->Length);

                    if (analyzer::UnicodeToAnsi(ValueName->Buffer, value.data(), ValueName->Length, NULL))
                    {
                        std::vector<std::string> args;

                        args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                        args.push_back(std::format(FORMAT_VALUE_NAME(value.c_str())));
                        args.push_back(std::format("Type: {{{:#010x}, \"{:s}\"}}", Type, strType.c_str()));
                        args.push_back(std::format(FORMAT_BUFFER(Data)));
                        args.push_back(std::format(FORMAT_SIZE(DataSize));
                        args.push_back(std::format(FORMAT_BINARY(binary)));

                        logger::LogEventWithTime(__FUNCTION__, args, NULL);
                    }
                }
            }
        }
    }
}

void OnQueryValueKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE KeyHandle = (HANDLE)args[0];
    IN PUNICODE_STRING ValueName = (PUNICODE_STRING)args[1];
    IN constants::key::KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass = (constants::key::KEY_VALUE_INFORMATION_CLASS)args[2];
    OUT PVOID KeyValueInformation = (PVOID)args[3];
    OUT PULONG ResultLength = (PULONG)args[5];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (ValueName && KeyValueInformation && ResultLength)
            {
                std::string type, name, strKeyValueClass, value;

                std::vector<uint8_t> binary((uint8_t*)KeyValueInformation, (uint8_t*)KeyValueInformation + READ_PTR(ResultLength));

                analyzer::GetStringFromEnums((uint32_t)KeyValueInformationClass, constants::key::keyValueInfoClass, strKeyValueClass);

                if (analyzer::QueryTypeObject(KeyHandle, type) && analyzer::QueryNameObject(KeyHandle, name))
                {
                    value.reserve(ValueName->Length);

                    if (analyzer::UnicodeToAnsi(ValueName->Buffer, value.data(), ValueName->Length, NULL))
                    {
                        std::vector<std::string> args;

                        args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                        args.push_back(std::format(FORMAT_VALUE_NAME(value.c_str())));
                        args.push_back(std::format("KeyValueInformationClass: {{{:#010x}, \"{:s}\"}}", (uint32_t)KeyValueInformationClass, strKeyValueClass.c_str()));
                        args.push_back(std::format(FORMAT_BUFFER(KeyValueInformation)));
                        args.push_back(std::format(FORMAT_BINARY(binary)));

                        logger::LogEventWithTime(__FUNCTION__, args, NULL);
                    }
                }
            }
        }
    }
}

void OnEnumerateKey(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE KeyHandle = (HANDLE)args[0];
    IN constants::key::KEY_VALUE_INFORMATION_CLASS KeyInformationClass = (constants::key::KEY_VALUE_INFORMATION_CLASS)args[2];
    OUT PVOID KeyInformation = (PVOID)args[3];
    OUT PULONG ResultLength = (PULONG)args[5];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (KeyInformation && ResultLength)
            {
                std::string type, name, strKeyValueClass;

                std::vector<uint8_t> binary((uint8_t*)KeyInformation, (uint8_t*)KeyInformation + READ_PTR(ResultLength));

                analyzer::GetStringFromEnums((uint32_t)KeyInformationClass, constants::key::keyValueInfoClass, strKeyValueClass);

                if (analyzer::QueryTypeObject(KeyHandle, type) && analyzer::QueryNameObject(KeyHandle, name))
                {
                    std::vector<std::string> args;

                    args.push_back(std::format(FORMAT_HANDLE(type.c_str(), name.c_str())));
                    args.push_back(std::format("KeyValueInformationClass: {{{:#010x}, \"{:s}\"}}", (uint32_t)KeyInformationClass, strKeyValueClass.c_str()));
                    args.push_back(std::format(FORMAT_BUFFER(KeyInformation)));
                    args.push_back(std::format(FORMAT_SIZE(READ_PTR(ResultLength)));
                    args.push_back(std::format(FORMAT_BINARY(binary)));

                    logger::LogEventWithTime(__FUNCTION__, args, NULL);
                }
            }
        }
    }
}

void OnGetContextThread(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ThreadHandle = (HANDLE)args[0];
    OUT PCONTEXT Context = (PCONTEXT)args[1];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (Context)
            {
                uint32_t tid = GetThreadId(ThreadHandle);

                std::vector<std::string> args;

                args.push_back(std::format(FORMAT_TID(tid)));
                args.push_back(std::format(FORMAT_THREAD_CONTEXT(READ_PTR(Context))));

                logger::LogEventWithTime(__FUNCTION__, args, NULL);
            }
        }
    }
}

void OnSetContextThread(uint32_t id, uint32_t* args, Registers* regs, void* jmp, std::vector<std::string>& strArguments, DbFunction& dbFunc, SyscallStatus& status)
{
    IN HANDLE ThreadHandle = (HANDLE)args[0];
    OUT PCONTEXT Context = (PCONTEXT)args[1];

    if (status == Executed)
    {
        if (regs->EAX == STATUS_SUCCESS)
        {
            if (Context)
            {
                uint32_t tid = GetThreadId(ThreadHandle);

                std::vector<std::string> args;

                args.push_back(std::format(FORMAT_TID(tid)));
                args.push_back(std::format(FORMAT_THREAD_CONTEXT(READ_PTR(Context))));

                logger::LogEventWithTime(__FUNCTION__, args, NULL);
            }
        }
    }
}