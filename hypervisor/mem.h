#ifndef MEM_H
#define MEM_H
#include <ntddk.h>
#include "vmx.h"

namespace mem 
{
    BOOLEAN AllocateVmxonRegion(IN vmx::VIRTUAL_MACHINE_STATE* GuestState);
    BOOLEAN AllocateVmcsRegion(IN vmx::VIRTUAL_MACHINE_STATE* GuestState);

    /// <summary>
    /// Converts a virtual address to a physical address...
    /// </summary>
    UINT64 VirtualToPhysicalAddress(void* Va);

    /// <summary>
    /// Converts a physical address to a virtual address...
    /// </summary>
    PVOID PhysicalToVirtualAddress(UINT64 Pa);
}
#endif

