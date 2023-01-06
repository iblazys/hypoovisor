#include "hypoovisor.h"
#include "processor.h"
#include "utils.h"
#include "memory.h"
#include "ept.h"
#include "vmcs.h"
#include <windef.h> // for BYTE*

VIRTUAL_MACHINE_STATE *g_GuestState;
UINT64 g_VirtualGuestMemoryAddress;
int g_ProcessorCounts;

BOOLEAN InitializeHV() 
{
    
	DbgPrint("[hypoo] Hypoovisor initializing...");

    // TODO: Check EPT Support, g_VirtualGuestMemoryAddress gets its address from here.
    EPT_POINTER* EPTp = InitializeEPTP();

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

    g_GuestState->Eptp = EPTp;

	return TRUE;
}

BOOLEAN RunHV() 
{
    for (size_t i = 0; i < (100 * PAGE_SIZE) - 1; i++)
    {
        void* TempAsm = "\xF4";
        memcpy(g_VirtualGuestMemoryAddress + i, TempAsm, 1);
    }

    //
    // Launching VM for Test (in the 0th virtual processor)
    //
    int ProcessorID = 0;

    LaunchVm(ProcessorID, g_GuestState->Eptp);
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
    *(UINT64*)AlignedVirtualBuffer = basic.VmcsRevisionId; // REVISION ID IS 1, DEFAULT IS 4 IN VmcsAuditor.exe

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

VOID LaunchVm(int ProcessorID, EPT_POINTER* EPTP)
{
    DbgPrint("\n======================== Launching VM =============================\n");

    KAFFINITY AffinityMask;
    AffinityMask = MathPower(2, ProcessorID);
    KeSetSystemAffinityThread(AffinityMask);

    DbgPrint("[hypoo]\t\tCurrent thread is executing in logical processor: %d \n", ProcessorID);

    PAGED_CODE();

    // Allocate stack for the VM Exit Handler
    UINT64 VMM_STACK_VA = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
    g_GuestState[ProcessorID].VmmStack = VMM_STACK_VA;

    if (g_GuestState[ProcessorID].VmmStack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack.\n");
        return;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].VmmStack, VMM_STACK_SIZE);

    // Allocate memory for MSRBitMap
    g_GuestState[ProcessorID].MsrBitmap = MmAllocateNonCachedMemory(PAGE_SIZE); // should be aligned, famous last words
    if (g_GuestState[ProcessorID].MsrBitmap == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].MsrBitmap, PAGE_SIZE);
    g_GuestState[ProcessorID].MsrBitmapPhysical = VirtualToPhysicalAddress(g_GuestState[ProcessorID].MsrBitmap);

    // Clear the VMCS State
    if (!ClearVmcsState(&g_GuestState[ProcessorID]))
    {
        DbgPrint("Failed to clear VMCS State");
        goto ErrorReturn;
    }

    // Load VMCS (Set the Current VMCS)
    if (!LoadVmcs(&g_GuestState[ProcessorID]))
    {
        DbgPrint("Failed to call __vmx_vmptrld()");
        goto ErrorReturn;
    }

    DbgPrint("[hypoo] Setting up VMCS...");
    SetupVmcs(&g_GuestState[ProcessorID], EPTP);

    DbgPrint("Executing VMLAUNCH");

    INT32 Status = __vmx_vmlaunch();

    if (Status != 0)
    {
        unsigned __int32 VMXError;
        __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &VMXError);
        //__vmx_vmread(0xfffffffe, &VMXError); VMCS_LAUNCH_STATE_FIELD_ENCODING, for auditor
        DbgPrint("VMLAUNCH Failed! VMLAUNCH returned [%d], VMX Error: 0x%0x", Status, VMXError);
    }

    // if VMLAUNCH succeeds will never be here!
    
    //ULONG64 ErrorCode = 0;
    //__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &ErrorCode);
    //__vmx_off();
    //DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
    //DbgBreakPoint();

    return TRUE;

ErrorReturn:
    DbgPrint("[*] Fail to setup VMCS !\n");
    return FALSE;
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

VOID MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    ULONG ExitReason = 0;
    __vmx_vmread(VMCS_EXIT_REASON, &ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &ExitQualification);

    DbgPrint("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    DbgPrint("\EXIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason)
    {
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case VMX_EXIT_REASON_EXECUTE_VMREAD:
    case VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case VMX_EXIT_REASON_EXECUTE_VMXON:
    case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    {
        break;
    }
    case VMX_EXIT_REASON_EXECUTE_HLT:
    {
        DbgPrint("[*] Execution of HLT detected... \n");

        //
        // that's enough for now ;)
        //
        AsmVmxoffAndRestoreState();

        break;
    }
    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    {
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_CPUID:
    {
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_INVD:
    {
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_VMCALL:
    {
        break;
    }

    case VMX_EXIT_REASON_MOV_CR:
    {
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDMSR:
    {
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_WRMSR:
    {
        break;
    }

    case VMX_EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    default:
    {
        // DbgBreakPoint();
        break;
    }
    }
}

VOID ResumeToNextInstruction()
{
    PVOID ResumeRIP = NULL;
    PVOID CurrentRIP = NULL;
    ULONG ExitInstructionLength = 0;

    __vmx_vmread(VMCS_GUEST_RIP, &CurrentRIP);
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitInstructionLength);

    ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(VMCS_GUEST_RIP, (ULONG64)ResumeRIP);
}

VOID VmResumeInstruction()
{
    __vmx_vmresume();

    // if VMRESUME succeeds will never be here !

    ULONG64 ErrorCode = 0;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go!
    // prefer to break
    //
    //DbgBreakPoint();
}
