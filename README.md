
# Process Observer
I made this utility to help with dynamic analysis of malicious files

## ObserverExe
This is an injector for ObserverDll that supports the following commands:

```
Author: @dastiwfantastiw
Usage: ./observer.exe [options]

Options:
-i      <file path>             Application file path (only 32-bit)
-a      <string>                Command line arguments
-j      <file path>             Path to special JSON config file
-d      <file path>             Path to observerDll
-s      <file path>             Path to save JSON as binary config
-r      <file path>             Path to read binary config
-h                              Show this help
-e                              Run the application and inject dll
```
Usage example:

``
Observer.exe -i sample.exe -j config.json -d ObserverDll.dll -e
``

## ObserverDll
This library contains the main functionality:
- Interception of system calls
> You can intercept any system call knowing only the module name and its name
- Analysis of parameters
> **The program knows nothing about function prototypes. The type of each parameter is determined based on the analysis.**
- Tracing information to a file
> All information is saved in a separate log file for each process

## JSON config
A correct configuration file should contain two key objects: `observer` and `syscalls`
```json
{
    "observer": {
        "syscalls": {
        }
    }
}
```
If you want to specify the path to the log file, then you should create key `log` inside the object `observer`. File path must not exceed `MAX_PATH (260)` characters:
```json
{
    "observer": {
    	"log": "C:\\Users\\username\\Desktop\\",
        "syscalls": {
        }
    }
}
```
Inside `syscalls` you must create an object with the name of the **module** in which you want to intercept system calls. For example:
```json
{
    "observer": {
        "log": "C:\\Users\\username\\Desktop\\",
        "syscalls": {
            "ntdll": {
            }
        }
    }
}
```
Each module/**function** can store the following keys:

| Key         |          Type   |                    Purpose|
|-------------|-----------------|---------------------------|
|`enabled`    | bool            | enable/disable monitoring    |
|`events`     | bool            | enable/disable custom events (details below) |
|`mode`       | string          | defines the system call tracing mode (details below)|
|`types`      | array of strings| defines the data types to be recognized (details below) |
|`maxPtr`     | number          | maximum number of pointers read|
|`minStrLen`  | number          | minimum string length for recognition|
|`maxStrLen`  | number          | maximum string length for recognition|
|**`functions`**  | object| an object that lists the names of functions that require individual settings|

### Modes

- `before`: trace a system call until it is executed
- `after`: trace a system call after it's executed
- `both`

### Types
The following types are currently available for recognition:

##### String formats
- `char`: char[]
- `wchar`: wchar_t[]
- `ansistring`: ANSI_STRING
- `unicodestring`: UNICODE_STRING
- `strings`: if you want to get all Strings

##### Handles
- `process`: HANDLE
- `file`: HANDLE
- `key`: HANDLE
- `thread`: HANDLE
- `section`: HANDLE
- `mutant`: HANDLE
- `event`: HANDLE
- `handles`: if you want to get all HANDLEs

#### functions
> If you need to set the settings for a specific function in a module, then you need to create its object in **`functions`** of this module like this:
```json
{
    "observer": {
        "log": "C:\\Users\\username\\Desktop\\",
        "syscalls": {
            "ntdll": {
                "enabled": true,
                "events": false,
                "functions": {
                    "NtMapViewOfSection": {
                        "mode": "before",
                        "types": [
                        ]
                    },
                    "NtOpenFile": {
                        "enabled": true,
                        "events": true
                    }
                },
                "maxPtr": 3,
                "maxStrLen": 256,
                "minStrLen": 3,
                "mode": "both",
                "types": [
                    "handles",
                    "strings"
                ]
            }
        }
    }
}
```
>***By default, each function inherits the settings of its module, but you can override them directly in it***
#### Custom event
This is a wrapper over a system call that shows more detailed information and **only works if the function succeeds**. For example:
```
#OnAllocateVirtualMemory (Process: {0x1220 (4640), "C:\Users\username\Desktop\sample.exe"}, BaseAddress: 0x01b70000, Size: 0x00080000 (524288 bytes), AllocationType: {0x00002000, "MEM_RESERVE"}, ProtectionType: {0x00000004, "PAGE_READWRITE"});
```

All available events are listed below (only for `ntdll` module):
 1. `OnCreateUserProcess`: **this event allows you to trace child processes**
 2. `OnOpenProcess`
 3. `OnAllocateVirtualMemory`
 4. `OnProtectVirtualMemory`
 5. `OnReadVirtualMemory`
 6. `OnWriteVirtualMemory`
 7. `OnWow64ReadVirtualMemory64`
 8. `OnWow64WriteVirtualMemory64`
 9. `OnReadFile`
 10. `OnWriteFile`
 11. `OnCreateFile`
 12. `OnOpenFile`
 13. `OnDeviceIoControlFile`
 14. `OnCreateKey`
 15. `OnDeleteKey`
 16. `OnDeleteValueKey`
 17. `OnSetValueKey`
 18. `OnQueryValueKey`
 19. `OnEnumerateKey`
 20. `OnGetContextThread`
 21. `OnSetContextThread`

## Log file structure

A log file contains the following information:
- Process information (PID, ImagePath, CommandLine and MD5 hash)
```
PID: 0x1220 (4640)
ImagePath: C:\Users\username\Desktop\sample.exe
CommandLine: "C:\Users\username\Desktop\sample.exe"
File MD5: 0441550329cd107f4bd0fbbb4cecbb30
```
- Common system calls information (Timestamp, ThreadID, FunctionName, Arguments, Result)
```
[22:21:59.519][13d8] NtClose (0x00000134 {Key: ["\REGISTRY\MACHINE\SOFTWARE\Microsoft\Ole"]});
[22:21:59.519][13d8] NtClose (0x00000134) => 0x00000000;
```
- Custom events (Timestamp, ThreadID, Prefix, FunctionName, Arguments)
```
[22:21:56.315][13d8] #OnOpenFile (File: "\Device\HarddiskVolume3\Windows\SysWOW64\uxtheme.dll", ShareAccess: {0x00000005, "FILE_SHARE_READ | FILE_SHARE_DELETE"}, OpenOptions: {0x00000060, "FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE"}, IOStatus: {0x00000000, "FILE_SUPERSEDED"});
```
```
[22:34:31.656][2020] #OnReadFile (File: "\Device\HarddiskVolume3\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config", Buffer: 0x01166fe0, Size: 0x00000fff (4095 bytes), <BINARY><?xml version="1.0" encoding="UTF-8" ?>...</BINARY>);
```

## Requirements
- WOW64 (Tested on Windows 10 and Windows 11)
- Only 32-bit applications
