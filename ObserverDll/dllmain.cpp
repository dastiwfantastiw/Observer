#include "observer_dll.h"

bool __stdcall DllMain(HMODULE hModule, DWORD dwReason, InjectData* data)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);
            CObserverDll* observerDll = CObserverDll::GetInstance();

            if (observerDll->Init(data))
            {
                observerDll->EnableHook();
            }

            break;
        }

        case DLL_PROCESS_DETACH:
        {
            CObserverDll* observerDll = CObserverDll::GetInstance();
            observerDll->Destroy();
            break;
        }
    }
    return true;
}