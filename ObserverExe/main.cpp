#include "observer_exe.h"

int main(int argc, char* argv[])
{
    printf(
        "Process Observer v%d.%d\n"
        "Author: @dastiwfantastiw\n\n",
        (OBSERVER_CONFIG_VERSION & 0xff00) >> 8,
        OBSERVER_CONFIG_VERSION & 0x00ff);

    RECT rectClient, rectWindow;
    HWND hWnd = GetConsoleWindow();

    GetClientRect(hWnd, &rectClient);
    GetWindowRect(hWnd, &rectWindow);

    MoveWindow(hWnd,
               GetSystemMetrics(SM_CXSCREEN) / 2 - (rectWindow.right - rectWindow.left) / 2,
               GetSystemMetrics(SM_CYSCREEN) / 2 - (rectWindow.bottom - rectWindow.top) / 2,
               1100,
               600,
               TRUE);

    CObserverExe observerExe;

    if (argc > 2)
    {
        for (int i = 1; i < argc; i++)
        {
            if (lstrcmpA(argv[i], "--image") == 0)
            {
                observerExe.AddProcess(argv[++i]);
                continue;
            }

            if (lstrcmpA(argv[i], "--cmdline") == 0)
            {
                observerExe.AddProcessCommandLine(argv[++i]);
                continue;
            }

            if (lstrcmpA(argv[i], "--json") == 0)
            {
                observerExe.GetConfigFromJson(argv[++i]);
                continue;
            }

            if (lstrcmpA(argv[i], "--dll") == 0)
            {
                observerExe.GetObserverDll(argv[++i]);
                continue;
            }

            if (lstrcmpA(argv[i], "--save") == 0)
            {
                observerExe.Save(argv[++i]);
                continue;
            }

            if (lstrcmpA(argv[i], "--load") == 0)
            {
                observerExe.Load(argv[++i]);
                continue;
            }

            if (lstrcmpA(argv[i], "--help") == 0)
            {
                observerExe.Help();
                continue;
            }

            if (lstrcmpiA(argv[i], "--execute") == 0)
            {
                observerExe.Execute(argv[i][2]);
                continue;
            }

            printf("[-] Unsupported command: %s\n", argv[i]);
            break;
        }
    }
    else
        observerExe.Help();

    system("pause");
    return 0;
}