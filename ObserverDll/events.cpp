#include "events.h"
#include "analyzer.h"
#include "events_args.h"
#include "memory.h"
#include "observer_dll.h"

#define READ_PTR(ptr) *ptr
#define DEFINE_CALLBACK(name) void name::Callback(SYSTEMTIME* time, uint32_t id, uint32_t* args, Registers* regs, void* jmp, CDbModule* dbModule, CDbFunction* dbFunc, SyscallStatus& status)

DEFINE_CALLBACK(OnCreateUserProcess)
{
    static const std::map<uint32_t, std::string> mapCreateProcessFlags = {
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

    static const std::map<uint32_t, std::string> mapCreateThreadFlags = {
        {THREAD_CREATE_FLAGS_CREATE_SUSPENDED, "CREATE_FLAGS_CREATE_SUSPENDED"},
        {THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH, "CREATE_FLAGS_SKIP_THREAD_ATTACH"},
        {THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, "CREATE_FLAGS_HIDE_FROM_DEBUGGER"},
        {THREAD_CREATE_FLAGS_LOADER_WORKER, "CREATE_FLAGS_LOADER_WORKER"},
        {THREAD_CREATE_FLAGS_SKIP_LOADER_INIT, "CREATE_FLAGS_SKIP_LOADER_INIT"},
        {THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE, "CREATE_FLAGS_BYPASS_PROCESS_FREEZE"},
        {THREAD_CREATE_FLAGS_INITIAL_THREAD, "CREATE_FLAGS_INITIAL_THREAD"}};

    PHANDLE phProcess = (PHANDLE)args[0];
    PHANDLE phThread = (PHANDLE)args[1];
    ACCESS_MASK ProcessFlags = args[6];
    ACCESS_MASK ThreadFlags = args[7];
    RTL_USER_PROCESS_PARAMETERS* pProcessParameters = (RTL_USER_PROCESS_PARAMETERS*)args[8];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                if (phProcess && phThread)
                {
                    CEventArgs args(m_Logger, __FUNCTION__);

                    args.AddProcess(phProcess);

                    std::string cmdLine;

                    if (pProcessParameters)
                    {
                        cmdLine.resize(pProcessParameters->CommandLine.Length);

                        CAnalyzer::UnicodeToAnsi(pProcessParameters->CommandLine.Buffer, cmdLine.data(), pProcessParameters->CommandLine.Length, NULL);
                    }

                    args.AddTid(phThread);
                    args.AddString("CommandLine", cmdLine.c_str());
                    args.AddStringFlags("CreateProcessFlags", ProcessFlags, &mapCreateProcessFlags);
                    args.AddStringFlags("CreateThreadFlags", ThreadFlags, &mapCreateThreadFlags);
                    args.LogEvent(time, dbModule, dbFunc, NULL);

                    CObserverDll* observerDll = CObserverDll::GetInstance();
                    if (observerDll)
                    {
                        observerDll->Migrate(*phProcess, *phThread);
                    }
                }
            }
        }
    }
}

DEFINE_CALLBACK(OnOpenProcess)
{
    OUT PHANDLE phProcess = (PHANDLE)args[0];
    IN ACCESS_MASK AccessMask = args[1];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                if (phProcess)
                {
                    CEventArgs args(m_Logger, __FUNCTION__);

                    args.AddProcess(phProcess);
                    args.AddStringFlags("Access", AccessMask, &CEventArgs::mapProcessAccessMaskFlags);
                    args.LogEvent(time, dbModule, dbFunc, NULL);
                }
            }
        }
    }
}

DEFINE_CALLBACK(OnAllocateVirtualMemory)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN OUT uint32_t* pBaseAddress = (uint32_t*)args[1];
    IN OUT uint32_t* pszRegion = (uint32_t*)args[3];
    IN uint32_t allocType = args[4];
    IN uint32_t protectType = args[5];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (pBaseAddress)
                    args.AddStringUint32("BaseAddress", READ_PTR(pBaseAddress));

                if (pszRegion)
                    args.AddStringSize32("RegionSize", READ_PTR(pszRegion));

                args.AddStringFlags("AllocationType", allocType, &CEventArgs::mapMemoryAllocFlags);
                args.AddStringFlags("ProtectionType", protectType, &CEventArgs::mapMemoryProtectFlags);
                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnWow64AllocateVirtualMemory64)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN OUT uint64_t* pBaseAddress = (uint64_t*)args[1];
    IN OUT uint64_t* pszRegion = (uint64_t*)args[4];
    IN uint32_t allocType = args[5];
    IN uint32_t protectType = args[6];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (pBaseAddress)
                    args.AddStringUint64("BaseAddress", READ_PTR(pBaseAddress));

                if (pszRegion)
                    args.AddStringSize64("RegionSize", READ_PTR(pszRegion));

                args.AddStringFlags("AllocationType", allocType, &CEventArgs::mapMemoryAllocFlags);
                args.AddStringFlags("ProtectionType", protectType, &CEventArgs::mapMemoryProtectFlags);
                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnProtectVirtualMemory)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN OUT uint32_t* pBaseAddress = (uint32_t*)args[1];
    IN OUT uint32_t* pNumberOfBytesToProtect = (uint32_t*)args[2];
    IN uint32_t NewAccessProtection = args[3];
    OUT uint32_t* pOldAccessProtection = (uint32_t*)args[4];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (pBaseAddress)
                    args.AddStringUint32("BaseAddress", READ_PTR(pBaseAddress));

                if (pNumberOfBytesToProtect)
                    args.AddStringSize32("Size", READ_PTR(pNumberOfBytesToProtect));

                args.AddStringFlags("NewProtection", NewAccessProtection, &CEventArgs::mapMemoryProtectFlags);

                if (pOldAccessProtection)
                    args.AddStringFlags("OldProtection", READ_PTR(pOldAccessProtection), &CEventArgs::mapMemoryProtectFlags);

                if (pBaseAddress && pNumberOfBytesToProtect && (hProcess == GetCurrentProcess()))
                {
                    if (NewAccessProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                        args.AddDump(READ_PTR(pBaseAddress), READ_PTR(pNumberOfBytesToProtect));
                }

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnWow64ProtectVirtualMemory64)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN OUT uint64_t* pBaseAddress = (uint64_t*)args[1];
    IN OUT uint64_t* pNumberOfBytesToProtect = (uint64_t*)args[2];
    IN uint32_t NewAccessProtection = args[3];
    OUT uint32_t* pOldAccessProtection = (uint32_t*)args[4];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (pBaseAddress)
                    args.AddStringUint64("BaseAddress", READ_PTR(pBaseAddress));

                if (pNumberOfBytesToProtect)
                    args.AddStringSize64("Size", READ_PTR(pNumberOfBytesToProtect));

                args.AddStringFlags("NewProtection", NewAccessProtection, &CEventArgs::mapMemoryProtectFlags);

                if (pOldAccessProtection)
                    args.AddStringFlags("OldProtection", READ_PTR(pOldAccessProtection), &CEventArgs::mapMemoryProtectFlags);

                if (pBaseAddress && pNumberOfBytesToProtect && (hProcess == GetCurrentProcess()))
                {
                    if (NewAccessProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                        args.AddDump(READ_PTR(pBaseAddress), READ_PTR(pNumberOfBytesToProtect));
                }

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnReadVirtualMemory)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN uint32_t BaseAddress = args[1];
    OUT uint32_t Buffer = args[2];
    IN uint32_t NumberOfBytesToRead = args[3];
    OUT OPTIONAL uint32_t* pNumberOfBytesReaded = (uint32_t*)args[4];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (BaseAddress)
                    args.AddStringUint32("BaseAddress", BaseAddress);

                args.AddStringUint32("Buffer", Buffer);
                args.AddStringSize32("SizeToRead", NumberOfBytesToRead);

                if (pNumberOfBytesReaded)
                {
                    args.AddStringSize32("SizeReaded", READ_PTR(pNumberOfBytesReaded));
                    args.AddDump(Buffer, READ_PTR(pNumberOfBytesReaded));
                }

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnWow64ReadVirtualMemory64)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN uint64_t BaseAddress = *(uint64_t*)&args[1];
    OUT uint32_t Buffer = args[3];
    IN uint64_t NumberOfBytesToRead = *(uint64_t*)&args[4];
    OUT OPTIONAL uint64_t* pNumberOfBytesReaded = (uint64_t*)args[6];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (BaseAddress)
                    args.AddStringUint64("BaseAddress", BaseAddress);

                args.AddStringUint32("Buffer", Buffer);
                args.AddStringSize64("SizeToRead", NumberOfBytesToRead);

                if (pNumberOfBytesReaded)
                {
                    args.AddStringSize64("SizeReaded", READ_PTR(pNumberOfBytesReaded));
                    args.AddDump<uint64_t>(Buffer, READ_PTR(pNumberOfBytesReaded));
                }

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnWriteVirtualMemory)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN uint32_t BaseAddress = args[1];
    OUT uint32_t Buffer = args[2];
    IN uint32_t NumberOfBytesToWrite = args[3];
    OUT OPTIONAL uint32_t* pNumberOfBytesWritten = (uint32_t*)args[4];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (BaseAddress)
                    args.AddStringUint32("BaseAddress", BaseAddress);

                args.AddStringUint32("Buffer", Buffer);
                args.AddStringSize32("SizeToWrite", NumberOfBytesToWrite);

                if (pNumberOfBytesWritten)
                    args.AddStringSize32("SizeWritten", READ_PTR(pNumberOfBytesWritten));

                args.AddDump(Buffer, NumberOfBytesToWrite);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnWow64WriteVirtualMemory64)
{
    IN HANDLE hProcess = (HANDLE)args[0];
    IN uint64_t BaseAddress = *(uint64_t*)&args[1];
    OUT uint32_t Buffer = args[3];
    IN uint64_t NumberOfBytesToWrite = *(uint64_t*)&args[4];
    OUT OPTIONAL uint64_t* pNumberOfBytesWritten = (uint64_t*)args[6];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);

                if (BaseAddress)
                    args.AddStringUint64("BaseAddress", BaseAddress);

                args.AddStringUint32("Buffer", Buffer);
                args.AddStringSize64("SizeToWrite", NumberOfBytesToWrite);

                if (pNumberOfBytesWritten)
                    args.AddStringSize64("SizeWritten", READ_PTR(pNumberOfBytesWritten));

                args.AddDump<uint64_t>(Buffer, NumberOfBytesToWrite);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnFreeVirtualMemory)
{
    HANDLE hProcess = (HANDLE)args[0];
    uint32_t BaseAddress = args[1];
    uint32_t* pRegionSize = (uint32_t*)args[2];
    uint32_t FreeType = args[3];

    switch (status)
    {
        case NotExecuted:
        {
            CEventArgs args(m_Logger, __FUNCTION__);

            if (hProcess != GetCurrentProcess())
                args.AddHandle(hProcess);

            args.AddStringUint32("BaseAddress", BaseAddress);

            if (pRegionSize)
                args.AddStringSize32("Size", READ_PTR(pRegionSize));

            uint32_t pageSize;

            if (hProcess == GetCurrentProcess() && pRegionSize &&
                !memory::IsBadReadAddress((void*)BaseAddress, &pageSize))
            {
                args.AddDump(BaseAddress, pageSize);
            }

            args.LogEvent(time, dbModule, dbFunc, NULL);
        }

        case Executed:
            break;
    }
}

DEFINE_CALLBACK(OnReadFile)
{
    IN HANDLE hFile = (HANDLE)args[0];
    OUT uint32_t Buffer = args[5];
    IN uint32_t Size = args[6];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hFile);
                args.AddStringUint32("Buffer", Buffer);
                args.AddStringSize32("Size", Size);

                args.AddDump(Buffer, Size);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnWriteFile)
{
    IN HANDLE hFile = (HANDLE)args[0];
    OUT uint32_t Buffer = args[5];
    IN uint32_t Size = args[6];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hFile);
                args.AddStringUint32("Buffer", Buffer);
                args.AddStringSize32("Size", Size);

                args.AddDump(Buffer, Size);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnCreateFile)
{
    OUT PHANDLE phFile = (PHANDLE)args[0];
    OUT PIO_STATUS_BLOCK pIoStatusBlock = (PIO_STATUS_BLOCK)args[3];
    IN uint32_t FileAttributes = args[5];
    IN uint32_t ShareAccess = args[6];
    IN uint32_t CreateDisposition = args[7];
    IN uint32_t CreateOptions = args[8];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(phFile);

                args.AddStringFlags("FileAttribute", FileAttributes, &CEventArgs::mapFileAttributesFlags);
                args.AddStringFlags("ShareAccess", ShareAccess, &CEventArgs::mapFileShareAccessFlags);
                args.AddStringFlags("CreateDisposition", CreateDisposition, &CEventArgs::mapFileCreateDispositionsFlags);
                args.AddStringFlags("CreateOptions", CreateOptions, &CEventArgs::mapFileCreateOptionsFlags);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnOpenFile)
{
    OUT PHANDLE phFile = (PHANDLE)args[0];
    IN uint32_t ShareAccess = args[4];
    IN uint32_t OpenOptions = args[5];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(phFile);

                args.AddStringFlags("ShareAccess", ShareAccess, &CEventArgs::mapFileShareAccessFlags);
                args.AddStringFlags("OpenAccess", OpenOptions, &CEventArgs::mapFileCreateOptionsFlags);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnDeviceIoControlFile)
{
    IN HANDLE hFile = (HANDLE)args[0];
    IN OPTIONAL uint32_t InputBuffer = args[6];
    IN uint32_t InputBufferLength = args[7];
    OUT OPTIONAL uint32_t OutputBuffer = args[8];
    IN uint32_t OutputBufferLength = args[9];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hFile);

                args.AddStringUint32("InputBuffer", InputBuffer);
                args.AddStringUint32("InputSize", InputBufferLength);

                args.AddStringUint32("OutputBuffer", OutputBuffer);
                args.AddStringUint32("OutputtSize", OutputBufferLength);

                if (InputBuffer)
                    args.AddDump(InputBuffer, InputBufferLength);

                if (OutputBuffer)
                    args.AddDump(OutputBuffer, OutputBufferLength);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnCreateKey)
{
    OUT PHANDLE phKey = (PHANDLE)args[0];
    IN uint32_t CreateOptions = args[5];
    OUT OPTIONAL uint32_t* Disposition = (uint32_t*)args[6];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(phKey);

                args.AddStringFlags("CreateOption", CreateOptions, &CEventArgs::mapKeyCreateOptionsFlags);

                if (Disposition)
                    args.AddStringFlags("CreateDisposition", READ_PTR(Disposition), &CEventArgs::mapKeyCreateDispositionsFlags);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnDeleteKey)
{
    IN HANDLE hKey = (HANDLE)args[0];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hKey);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnDeleteValueKey)
{
    IN HANDLE hKey = (HANDLE)args[0];
    IN PUNICODE_STRING ValueName = (PUNICODE_STRING)args[1];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hKey);

                args.AddUnicodeString("ValueName", ValueName);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnSetValueKey)
{
    IN HANDLE hKey = (HANDLE)args[0];
    IN PUNICODE_STRING ValueName = (PUNICODE_STRING)args[1];
    IN uint32_t Type = args[3];
    IN uint32_t Data = args[4];
    IN uint32_t DataSize = args[5];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hKey);

                args.AddUnicodeString("ValueName", ValueName);
                args.AddStringFlags("Type", Type, &CEventArgs::mapKeyTypesFlags);
                args.AddStringUint32("Data", Data);
                args.AddStringSize32("Size", DataSize);

                if (Data)
                    args.AddDump(Data, DataSize);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnQueryValueKey)
{
    IN HANDLE hKey = (HANDLE)args[0];
    IN PUNICODE_STRING ValueName = (PUNICODE_STRING)args[1];
    IN uint32_t KeyValueInformationClass = args[2];
    OUT uint32_t KeyValueInformation = args[3];
    OUT uint32_t* ResultLength = (uint32_t*)args[5];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hKey);

                args.AddUnicodeString("ValueName", ValueName);
                args.AddStringFlags("InfoClass", KeyValueInformationClass, &CEventArgs::mapKeyValueInfoClass);
                args.AddStringUint32("Buffer", KeyValueInformation);

                if (ResultLength)
                    args.AddStringSize32("Size", READ_PTR(ResultLength));

                if (KeyValueInformation && ResultLength)
                    args.AddDump(KeyValueInformation, READ_PTR(ResultLength));

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnEnumerateKey)
{
    IN HANDLE hKey = (HANDLE)args[0];
    IN uint32_t KeyInformationClass = args[2];
    OUT uint32_t KeyInformation = args[3];
    OUT uint32_t* ResultLength = (uint32_t*)args[5];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hKey);

                args.AddStringFlags("InfoClass", KeyInformationClass, &CEventArgs::mapKeyValueInfoClass);
                args.AddStringUint32("Buffer", KeyInformation);

                if (ResultLength)
                    args.AddStringSize32("Size", READ_PTR(ResultLength));

                if (KeyInformation && ResultLength)
                    args.AddDump(KeyInformation, READ_PTR(ResultLength));

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnGetContextThread)
{
    IN HANDLE hThread = (HANDLE)args[0];
    OUT PCONTEXT Context = (PCONTEXT)args[1];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddTid(hThread);
                args.AddThreadContext(Context);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnSetContextThread)
{
    IN HANDLE hThread = (HANDLE)args[0];
    OUT PCONTEXT Context = (PCONTEXT)args[1];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddTid(hThread);
                args.AddThreadContext(Context);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnCreateThreadEx)
{
    OUT PHANDLE hThread = (PHANDLE)args[0];
    IN HANDLE hProcess = (HANDLE)args[3];
    IN uint32_t lpStartAddress = args[4];
    IN uint32_t lpParameter = args[5];
    IN uint32_t Flags = args[6];
    IN uint32_t StackZeroBits = args[7];
    IN uint32_t SizeOfStackCommit = args[8];
    IN uint32_t SizeOfStackReserve = args[9];
    OUT uint32_t lpBytesBuffer = args[10];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddProcess(hProcess);
                args.AddTid(hThread);
                args.AddStringUint32("StartAddress", lpStartAddress);
                args.AddStringUint32("Parameter", lpParameter);

                uint32_t pgSize;

                if (lpStartAddress && !memory::IsBadReadAddress((void*)lpStartAddress, &pgSize))
                {
                    args.AddDump(lpStartAddress, min(256, pgSize));
                }

                if (lpParameter && !memory::IsBadReadAddress((void*)lpParameter, &pgSize))
                {
                    args.AddDump(lpParameter, min(256, pgSize));
                }

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnCreateSection)
{
    OUT PHANDLE phSection = (PHANDLE)args[0];
    IN ACCESS_MASK DesiredAccess = args[1];
    IN uint32_t PageProtection = args[4];
    IN uint32_t SectionAttributes = args[5];
    IN OPTIONAL HANDLE hFile = (HANDLE)args[6];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(phSection);

                if (hFile)
                {
                    args.AddHandle(hFile);
                }

                args.AddStringFlags("Access", DesiredAccess, &CEventArgs::mapSectionAccessFlags);
                args.AddStringFlags("Protection", PageProtection, &CEventArgs::mapMemoryProtectFlags);
                args.AddStringFlags("Attributes", SectionAttributes, &CEventArgs::mapSectionAttribFlags);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}

DEFINE_CALLBACK(OnMapViewOfSection)
{
    IN HANDLE hSection = (HANDLE)args[0];
    IN HANDLE hProcess = (HANDLE)args[1];
    IN OUT uint32_t* pBaseAddress = (uint32_t*)args[2];
    IN uint32_t CommitSize = args[4];
    IN uint32_t* pViewSize = (uint32_t*)args[6];
    IN uint32_t AllocationType = args[8];

    switch (status)
    {
        case NotExecuted:
            break;

        case Executed:
        {
            if (regs->EAX == STATUS_SUCCESS)
            {
                CObserverDll* observerDll = CObserverDll::GetInstance();
                if (observerDll)
                {
                    observerDll->CheckWaitList();
                }

                CEventArgs args(m_Logger, __FUNCTION__);

                args.AddHandle(hSection);
                args.AddProcess(hProcess);

                if (pBaseAddress)
                    args.AddStringUint32("BaseAddress", READ_PTR(pBaseAddress));

                args.AddStringUint32("CommitSize", CommitSize);

                if (pViewSize)
                    args.AddStringUint32("ViewSize", READ_PTR(pViewSize));

                args.AddStringFlags("AllocationType", AllocationType, &CEventArgs::mapMemoryAllocFlags);

                args.LogEvent(time, dbModule, dbFunc, NULL);
            }
        }
    }
}