#include "hypoovisor.h"
#include "processor.h"
#include "utils.h"
#include "memory.h"

#include <ia32.h>
#include <windef.h>

VIRTUAL_MACHINE_STATE *g_GuestState;
int g_ProcessorCounts;

BOOLEAN InitializeHV() 
{
	DbgPrint("[hypoo] Hypoovisor initializing...");

    if (!IsVMXSupported()) 
    {
        DbgPrint("[hypoo] VMX is not supported on this processor.");
        return FALSE;
    }

    g_ProcessorCounts = KeQueryActiveProcessorCount(0);
    g_GuestState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * g_ProcessorCounts, POOLTAG);

    KAFFINITY AffinityMask;
    for (size_t i = 0; i < g_ProcessorCounts; i++) // count lol
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);

        DbgPrint("=====================================================");
        DbgPrint("[hypoo] Current thread is executing in logical processor: %d", i);

        AsmEnableVmxOperation(); // lets move this into C eventually?

        DbgPrint("[hypoo] VMX Operation Enabled Successfully !");

        if (!AllocateVmxonRegion(&g_GuestState[i]))
            return FALSE;

        if (!AllocateVmcsRegion(&g_GuestState[i]))
            return FALSE;

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[i].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[i].VmxonRegion);

        DbgPrint("\n=====================================================\n");
    }

	return TRUE;
}

BOOLEAN StopHV() 
{
    TerminateVmx();

    return TRUE;
}

// This code is the same as AllocateVmcsRegion, change it so we arent duplicating code
BOOLEAN AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE* GuestState)
{
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;

    int    VMXONSize = 2 * VMXON_SIZE;
    BYTE* Buffer = MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
    Highest.QuadPart = ~0;

    // BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE*)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE*)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMXON at %llx", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMXON at %llx", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMXON at %llx", AlignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_REGISTER basic = { 0 };

    basic.AsUInt = GetHostMSR(IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.VmcsRevisionId);

    // Changing Revision Identifier
    *(UINT64*)AlignedVirtualBuffer = basic.VmcsRevisionId;

    int Status = __vmx_on(&AlignedPhysicalBuffer);

    if (Status)
    {
        DbgPrint("[*] VMXON failed with status %d\n", Status);
        return FALSE;
    }

    GuestState->VmxonRegion = AlignedPhysicalBuffer;

    return TRUE;
}

// This code is the same as AllocateVmxonRegion, change it so we arent duplicating code
BOOLEAN AllocateVmcsRegion(IN VIRTUAL_MACHINE_STATE* GuestState)
{
    //
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    //
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;

    int    VMCSSize = 2 * VMCS_SIZE;
    BYTE* Buffer = MmAllocateContiguousMemory(VMCSSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
    Highest.QuadPart = ~0;

    // BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);
    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMCS Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE*)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE*)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMCS at %llx", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMCS at %llx", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMCS at %llx", AlignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_REGISTER basic = { 0 };

    basic.AsUInt = __readmsr(IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.VmcsRevisionId);

    // Changing Revision Identifier
    *(UINT64*)AlignedVirtualBuffer = basic.VmcsRevisionId;

    int Status = __vmx_vmptrld(&AlignedPhysicalBuffer);

    if (Status)
    {
        DbgPrint("[hypoo] VMCS failed with status %d\n", Status);
        return FALSE;
    }

    GuestState->VmcsRegion = AlignedPhysicalBuffer;

    return TRUE;
}

VOID TerminateVmx()
{
    DbgPrint("\n[hypoo] Terminating VMX...\n");

    KAFFINITY AffinityMask;
    for (size_t i = 0; i < g_ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);
        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

        __vmx_off();

        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
    }

    DbgPrint("[hypoo] VMX Operation turned off successfully. \n");
}
