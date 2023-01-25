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

BOOLEAN AllocateVMRegion(REGIONTYPE Type, IN VIRTUAL_MACHINE_STATE* GuestState)
{
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;

    int RegionSize = 2 * VMXON_SIZE; // might need to change this if I decide to go above 4096 bytes

    BYTE* Buffer = MmAllocateContiguousMemory(RegionSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
    Highest.QuadPart = ~0;

    // BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    // Zero-out memory
    RtlSecureZeroMemory(Buffer, RegionSize + ALIGNMENT_PAGE_SIZE);

    // Align the buffers
    UINT64 AlignedPhysicalBuffer = (BYTE*)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
    UINT64 AlignedVirtualBuffer = (BYTE*)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer at %llx", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer at %llx", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated at %llx", AlignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_REGISTER basic = { 0 };

    basic.AsUInt = GetHostMSR(IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.VmcsRevisionId);

    // Changing Revision Identifier
    *(UINT64*)AlignedVirtualBuffer = basic.VmcsRevisionId; // REVISION ID IS 1, DEFAULT IS 4 IN VmcsAuditor.exe

    if (Type == REGION_VMXON)
    {
        int Status = __vmx_on(&AlignedPhysicalBuffer);

        if (Status)
        {
            DbgPrint("[hypoo] VMXON failed with status %d\n", Status);
            return FALSE;
        }

        GuestState->VmxonRegion = AlignedPhysicalBuffer;
    }
    else
    {
        // If LoadVmcs() does this then why are we doing it here or vice versa??
        int Status = __vmx_vmptrld(&AlignedPhysicalBuffer);

        if (Status)
        {
            DbgPrint("[hypoo] VMCS failed with status %d\n", Status);
            return FALSE;
        }

        GuestState->VmcsRegion = AlignedPhysicalBuffer;
    }

    return TRUE;
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