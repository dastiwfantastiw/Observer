#include "Memory.h"
#pragma init_seg(compiler)

namespace memory {

HANDLE Heap = HeapCreate(0, 0, 0);
fRtlAllocateHeap RtlAllocateHeap =
    (fRtlAllocateHeap)GetProcAddress(LoadLibraryA("ntdll"), "RtlAllocateHeap");
fRtlFreeHeap RtlFreeHeap =
    (fRtlFreeHeap)GetProcAddress(LoadLibraryA("ntdll"), "RtlFreeHeap");

} // namespace memory

bool memory::IsBadReadAddress(void* address, uint32_t* szPage)
{
    MEMORY_BASIC_INFORMATION memBasic = {0};

    if (!VirtualQuery(address, &memBasic, sizeof(memBasic)))
    {
        return true;
    }

    if (memBasic.Protect & (PAGE_GUARD | PAGE_NOACCESS))
    {
        return true;
    }

    if (memBasic.Protect &
        (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
    {
        if (szPage)
        {
            *szPage = ((uint32_t)memBasic.BaseAddress + memBasic.RegionSize) -
                             (uint32_t)address;
        }
        return false;
    }
    return true;
}

void* __cdecl operator new(size_t size)
{
    return memory::RtlAllocateHeap(memory::Heap, 0, size);
}

void __cdecl operator delete(void* mem)
{
    memory::RtlFreeHeap(memory::Heap, 0, mem);
}
