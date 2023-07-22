#include "events_args.h"
#include "analyzer.h"

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

const MapFlags CEventArgs::mapMemoryAllocFlags =
    {{MEM_COMMIT, "MEM_COMMIT"},
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

const MapFlags CEventArgs::mapProcessAccessMaskFlags =
    {{PROCESS_TERMINATE, "PROCESS_TERMINATE"},
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

const MapFlags CEventArgs::mapMemoryProtectFlags =
    {{PAGE_NOACCESS, "PAGE_NOACCESS"},
     {PAGE_READONLY, "PAGE_READONLY"},
     {PAGE_READWRITE, "PAGE_READWRITE"},
     {PAGE_WRITECOPY, "PAGE_WRITECOPY"},
     {PAGE_EXECUTE, "PAGE_EXECUTE"},
     {PAGE_EXECUTE_READ, "PAGE_EXECUTE_READ"},
     {PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE"},
     {PAGE_EXECUTE_WRITECOPY, "PAGE_EXECUTE_WRITECOPY"},
     {PAGE_GUARD, "PAGE_GUARD"},
     {PAGE_NOCACHE, "PAGE_NOCACHE"}};

const MapFlags CEventArgs::mapFileAttributesFlags =
    {{FILE_ATTRIBUTE_READONLY, "FILE_ATTRIBUTE_READONLY"},
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

const MapFlags CEventArgs::mapFileShareAccessFlags =
    {{FILE_SHARE_READ, "FILE_SHARE_READ"},
     {FILE_SHARE_WRITE, "FILE_SHARE_WRITE"},
     {FILE_SHARE_DELETE, "FILE_SHARE_DELETE"}};

const MapFlags CEventArgs::mapFileCreateDispositionsFlags =
    {{FILE_SUPERSEDE, "FILE_SUPERSEDE"},
     {FILE_OPEN, "FILE_OPEN"},
     {FILE_CREATE, "FILE_CREATE"},
     {FILE_OPEN_IF, "FILE_OPEN_IF"},
     {FILE_OVERWRITE, "FILE_OVERWRITE"},
     {FILE_MAXIMUM_DISPOSITION, "FILE_MAXIMUM_DISPOSITION"}};

const MapFlags CEventArgs::mapFileCreateOptionsFlags =
    {{FILE_DIRECTORY_FILE, "FILE_DIRECTORY_FILE"},
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
     {FILE_VALID_SET_FLAGS, "FILE_VALID_SET_FLAGS"}};

const MapFlags CEventArgs::mapKeyCreateDispositionsFlags =
    {{REG_CREATED_NEW_KEY, "REG_CREATED_NEW_KEY"},
     {REG_OPENED_EXISTING_KEY, "REG_OPENED_EXISTING_KEY"}};

const MapFlags CEventArgs::mapKeyCreateOptionsFlags =
    {{REG_OPTION_RESERVED, "REG_OPTION_RESERVED"},
     {REG_OPTION_NON_VOLATILE, "REG_OPTION_NON_VOLATILE"},
     {REG_OPTION_CREATE_LINK, "REG_OPTION_CREATE_LINK"},
     {REG_OPTION_BACKUP_RESTORE, "REG_OPTION_BACKUP_RESTORE"},
     {REG_OPTION_OPEN_LINK, "REG_OPTION_OPEN_LINK"},
     {REG_OPTION_DONT_VIRTUALIZE, "REG_OPTION_DONT_VIRTUALIZE"}};

const MapFlags CEventArgs::mapKeyTypesFlags =
    {{REG_NONE, "REG_NONE"},
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

const MapFlags CEventArgs::mapKeyValueInfoClass =
    {{KeyValueBasicInformation, "KeyValueBasicInformation"},
     {KeyValueFullInformation, "KeyValueFullInformation"},
     {KeyValuePartialInformation, "KeyValuePartialInformation"},
     {KeyValueFullInformationAlign64, "KeyValueFullInformationAlign64"},
     {KeyValuePartialInformationAlign64, "KeyValuePartialInformationAlign64"},
     {KeyValueLayerInformation, "KeyValueLayerInformation"},
     {MaxKeyValueInfoClass, "MaxKeyValueInfoClass"}};

const MapFlags CEventArgs::mapSectionAttribFlags =
    {{SEC_HUGE_PAGES, "SEC_HUGE_PAGES"},
     {SEC_PARTITION_OWNER_HANDLE, "SEC_PARTITION_OWNER_HANDLE"},
     {SEC_64K_PAGES, "SEC_64K_PAGES"},
     {SEC_FILE, "SEC_FILE"},
     {SEC_IMAGE, "SEC_IMAGE"},
     {SEC_PROTECTED_IMAGE, "SEC_PROTECTED_IMAGE"},
     {SEC_RESERVE, "SEC_RESERVE"},
     {SEC_COMMIT, "SEC_COMMIT"},
     {SEC_NOCACHE, "SEC_NOCACHE"},
     {SEC_WRITECOMBINE, "SEC_WRITECOMBINE"},
     {SEC_LARGE_PAGES, "SEC_LARGE_PAGES"}};

const MapFlags CEventArgs::mapSectionAccessFlags =
    {{SECTION_QUERY, "SECTION_QUERY"},
     {SECTION_MAP_WRITE, "SECTION_MAP_WRITE"},
     {SECTION_MAP_READ, "SECTION_MAP_READ"},
     {SECTION_MAP_EXECUTE, "SECTION_MAP_EXECUTE"},
     {SECTION_EXTEND_SIZE, "SECTION_EXTEND_SIZE"},
     {SECTION_MAP_EXECUTE_EXPLICIT, "SECTION_MAP_EXECUTE_EXPLICIT"}};

void CEventArgs::AddHandle(HANDLE handle)
{
    std::string type, name;

    if (CAnalyzer::QueryObject(ObjectTypeInformation, handle, type) &&
        CAnalyzer::QueryObject(ObjectNameInformation, handle, name))
    {
        m_Args.push_back(std::format("{:s}: \"{:s}\"", type.c_str(), name.c_str()));
    }
}

void CEventArgs::AddHandle(HANDLE* pHandle)
{
    return AddHandle(*pHandle);
}

void CEventArgs::AddProcess(HANDLE handle)
{
    uint32_t pid = GetProcessId(handle);

    if (pid)
    {
        std::string imagePath;

        if (CAnalyzer::QueryProcessImage(handle, imagePath))
        {
            m_Args.push_back(std::format("Process: {{{:#x} ({:d}), \"{:s}\"}}", pid, pid, imagePath.c_str()));
        }
    }
}

void CEventArgs::AddProcess(HANDLE* pHandle)
{
    return AddProcess(*pHandle);
}

void CEventArgs::AddTid(HANDLE handle)
{
    uint32_t tid = GetThreadId(handle);

    if (tid)
    {
        m_Args.push_back(std::format("Tid: {:#x} ({:d})", tid, tid));
    }
}

void CEventArgs::AddTid(HANDLE* pHandle)
{
    return AddTid(*pHandle);
}

void CEventArgs::AddStringFlags(const char* name, uint32_t value, const MapFlags* mapconsts)
{
    std::string strConsts;

    GetStringFromMask(value, mapconsts, strConsts);

    if (strConsts.empty())
        return;

    m_Args.push_back(std::format("{}: {{{:#010x}, \"{:s}\"}}", name, value, strConsts.c_str()));
}

void CEventArgs::AddStringSize32(const char* name, uint32_t value)
{
    m_Args.push_back(std::format("{}: {:#010x} ({:d} bytes)", name, value, value));
}

void CEventArgs::AddStringSize32(const char* name, uint32_t* pValue)
{
    return AddStringSize32(name, *pValue);
}

void CEventArgs::AddStringSize64(const char* name, uint64_t value)
{
    m_Args.push_back(std::format("{}: {:#020x} ({:d} bytes)", name, value, value));
}

void CEventArgs::AddStringSize64(const char* name, uint64_t* pValue)
{
    return AddStringSize64(name, *pValue);
}

void CEventArgs::AddString(const char* name, const char* value)
{
    m_Args.push_back(std::format("{}: \"{:s}\"", name, value));
}

void CEventArgs::AddStringUint32(const char* name, uint32_t value)
{
    m_Args.push_back(std::format("{}: {:#010x}", name, value));
}

void CEventArgs::AddStringUint64(const char* name, uint64_t value)
{
    m_Args.push_back(std::format("{}: {:#020x}", name, value));
}

void CEventArgs::AddUnicodeString(const char* name, UNICODE_STRING* value)
{
    if (value)
    {
        std::string ansi;
        ansi.resize(value->Length + 1);

        CAnalyzer::UnicodeToAnsi(value->Buffer, ansi.data(), ansi.size(), NULL);

        if (ansi.empty())
            return;

        return AddString(name, ansi.c_str());
    }
}

void CEventArgs::AddThreadContext(CONTEXT* ctx)
{
    m_Args.push_back(std::format("{}", *ctx));
}

bool CEventArgs::LogEvent(SYSTEMTIME* time, CDbModule* dbModule, CDbFunction* dbFunc, uint32_t* ntstatus)
{
    std::string arguments;

    for (size_t i = 0; i < m_Args.size(); i++)
    {
        arguments += m_Args[i];

        if (i != m_Args.size() - 1)
        {
            arguments += ", ";
        }
    }

    return ntstatus ? m_Logger.LogFormat("[{:02d}:{:02d}:{:02d}.{:03d}][{:x}][{:04x}] #{:s} ({:s}) => 0x{:08x};\n",
                                         time->wHour,
                                         time->wMinute,
                                         time->wSecond,
                                         time->wMilliseconds,
                                         GetCurrentProcessId(),
                                         GetCurrentThreadId(),
                                         m_EventName.c_str(),
                                         arguments,
                                         *ntstatus)
                    : m_Logger.LogFormat("[{:02d}:{:02d}:{:02d}.{:03d}][{:x}][{:04x}] #{:s} ({:s});\n",
                                         time->wHour,
                                         time->wMinute,
                                         time->wSecond,
                                         time->wMilliseconds,
                                         GetCurrentProcessId(),
                                         GetCurrentThreadId(),
                                         m_EventName.c_str(),
                                         arguments);
}
