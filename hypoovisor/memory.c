#include "memory.h"

UINT64 AllocateVMMStack()
{
    UINT64 VMM_STACK_VA = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);

    if (VMM_STACK_VA == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack.\n");
        return NULL;
    }

    RtlZeroMemory(VMM_STACK_VA, VMM_STACK_SIZE);

    return VMM_STACK_VA;
}

UINT64 AllocateMSRBitmap()
{   
    // should be aligned, famous last words
    UINT64 MSRBitmap_VA = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG); //MmAllocateNonCachedMemory(PAGE_SIZE); 

    if (MSRBitmap_VA == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return NULL;
    }

    RtlZeroMemory(MSRBitmap_VA, PAGE_SIZE);

    return MSRBitmap_VA;
}

UINT64 VirtualToPhysicalAddress(void* Va)
{
    return MmGetPhysicalAddress(Va).QuadPart;
}

UINT64 PhysicalToVirtualAddress(UINT64 Pa)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = Pa;

    return MmGetVirtualForPhysical(PhysicalAddr);
}