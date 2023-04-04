#include "observer_exe.h"

using namespace observer_exe;

void help()
{
    printf(
        "Author: @dastiwfantastiw\n"
        "Usage: ./observer.exe [options]\n\n"
        "Options:\n"
        "-i\t<file path>\t\tApplication file path (only 32-bit)\n"
        "-a\t<string>\t\tCommand line arguments\n"
        "-j\t<file path>\t\tPath to special JSON config file\n"
        "-d\t<file path>\t\tPath to observerDll\n"
        "-s\t<file path>\t\tPath to save JSON as binary config\n"
        "-r\t<file path>\t\tPath to read binary config\n"
        "-h\t \t\t\tShow this help\n"
        "-e\t \t\t\tRun the application and inject dll\n");
}

int main(int argc, char* argv[])
{
    RECT rectClient, rectWindow;
    HWND hWnd = GetConsoleWindow();

    GetClientRect(hWnd, &rectClient);
    GetWindowRect(hWnd, &rectWindow);

    int posx = GetSystemMetrics(SM_CXSCREEN) / 2 -
               (rectWindow.right - rectWindow.left) / 2;
    int posy = GetSystemMetrics(SM_CYSCREEN) / 2 -
               (rectWindow.bottom - rectWindow.top) / 2;

    MoveWindow(hWnd, posx, posy, 1100, 600, TRUE);

    if (argc < 2)
    {
        help();
    }
    else
    {
        ObserverExe observer;

        for (uint32_t i = 0; i < argc; i++)
        {
            if (argv[i][0] == '-' || argv[i][0] == '/')
            {
                switch (argv[i][1])
                {
                    case 'i':
                        observer.GetProcessImagePath(argv[++i]);
                        break;
                    case 'a':
                        observer.GetProcessCommandLine(argv[++i]);
                        break;
                    case 'j':
                        observer.GetJson(argv[++i]);
                        break;
                    case 'd':
                        observer.GetDll(argv[++i]);
                        break;
                    case 's':
                        observer.SaveBinaryToFile(argv[++i]);
                        break;
                    case 'r':
                        observer.ReadBinaryFromFile(argv[++i]);
                        break;
                    case 'e':
                    case 'E':
                        observer.Execute(argv[i][1] == 'e' ? false : true);
                        break;
                    default:
                        help();
                        break;
                }
            }
        }
    }
    system("pause");
    return 0;
}
