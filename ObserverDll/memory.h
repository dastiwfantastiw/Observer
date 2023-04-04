#pragma once
#include <Windows.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")

typedef PVOID(NTAPI* fRtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, ULONG Size);
typedef BOOLEAN(NTAPI* fRtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);

namespace memory {

extern HANDLE Heap;
extern fRtlAllocateHeap RtlAllocateHeap;
extern fRtlFreeHeap RtlFreeHeap;

bool IsBadReadAddress(void* address, uint32_t* availableSize);
} // namespace memory

extern void* __cdecl operator new(size_t size);

extern void __cdecl operator delete(void* mem);