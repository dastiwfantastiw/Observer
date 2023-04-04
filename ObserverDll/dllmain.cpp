#include "observer_dll.h"

bool __stdcall DllMain(HMODULE hModule, DWORD dwReason, inject::ObserverDllData* InjectData)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (observer_dll::InitFromConfig(hModule, InjectData))
            {
                return observer_dll::InstallHook();
            }
        }
    }
    return true;
}