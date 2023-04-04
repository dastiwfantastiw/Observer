#include "analyzer.h"
#include "db.h"
#include "observer_dll.h"

SyscallStatus WINAPI observer_dll::SyscallHandler(uint32_t id, uint32_t* args, Registers* regs, void* jmpAddress)
{
    SyscallStatus status = NotExecuted;
    SYSTEMTIME time;

    if (DbFunctions->contains(id))
    {
        EnableGuardForThread();

        std::vector<std::string> arguments;

        DbFunction dbFunc = DbFunctions->at(id);
        if ((dbFunc.Mode & Mode::ModeBefore) && status == NotExecuted)
        {
            GetLocalTime(&time);
            arguments.resize(dbFunc.Argc);

            analyzer::AnalyzeFunctionArgs(args, dbFunc.Types, dbFunc.MaxPtr, dbFunc.MinStrLen, dbFunc.MaxStrLen, arguments);
            logger::LogFunction(time, dbFunc, arguments, 0);
        }

        if (dbFunc.EventEnabled && dbFunc.EventHandler)
        {
            dbFunc.EventHandler(id, args, regs, jmpAddress, arguments, dbFunc, status);
        }

        if (status == NotExecuted)
        {
            DisableGuardForThread();
            ExecuteSystemCall(id, dbFunc.Argc, args, regs, jmpAddress);
            EnableGuardForThread();
            status = Executed;
        }

        if ((dbFunc.Mode & Mode::ModeAfter) && status == Executed)
        {
            arguments.clear();
            arguments.resize(dbFunc.Argc);

            GetLocalTime(&time);

            analyzer::AnalyzeFunctionArgs(args, dbFunc.Types, dbFunc.MaxPtr, dbFunc.MinStrLen, dbFunc.MaxStrLen, arguments);
            logger::LogFunction(time, dbFunc, arguments, &regs->EAX);
        }

        if (dbFunc.EventEnabled && dbFunc.EventHandler)
        {
            dbFunc.EventHandler(id, args, regs, jmpAddress, arguments, dbFunc, status);
        }

        DisableGuardForThread();
    }

    return status;
}

GuardStatus WINAPI observer_dll::ThreadGuard(uint32_t id)
{
    GuardStatus status = DontSkip;
    if ((uint32_t)TlsGetValue(Guard) == (uint32_t)GetCurrentThreadId())
    {
        status = Skip;
    }
    return status;
}