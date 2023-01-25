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

/// <summary>
/// Check processor support features and initialize VMX/EPT.
/// </summary>
/// <returns></returns>
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

        
        if(!AllocateVMRegion(REGION_VMXON, &g_GuestState[i]))
            return FALSE;

        if (!AllocateVMRegion(REGION_VMCS, &g_GuestState[i]))
            return FALSE;
            
        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[i].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[i].VmxonRegion);

        DbgPrint("\n=====================================================\n");
    }

    g_GuestState->Eptp = EPTp;

	return TRUE;
}

/// <summary>
/// Virtualize the currently running system.
/// </summary>
/// <returns></returns>
BOOLEAN RunHV() 
{
    int LogicalProcessorsCount = 1; // change to all processors; debug

    for (size_t i = 0; i < LogicalProcessorsCount; i++)
    {
        g_GuestState[i].VmmStack = AllocateVMMStack();
        g_GuestState[i].MsrBitmap = AllocateMSRBitmap();
        g_GuestState[i].MsrBitmapPhysical = VirtualToPhysicalAddress(g_GuestState[i].MsrBitmap);

        RunOnProcessor(i, g_GuestState->Eptp, VMXSaveState);
    }
}

/// <summary>
/// 
/// </summary>
/// <returns></returns>
BOOLEAN StopHV() 
{
    TerminateVmx();

    return TRUE;
}

/// <summary>
/// 
/// </summary>
BOOLEAN RunOnProcessor(ULONG ProcessorNumber, EPT_POINTER* EPTP, PFUNC Routine)
{
    KIRQL OldIrql;

    KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

    OldIrql = KeRaiseIrqlToDpcLevel();

    Routine(ProcessorNumber, EPTP);

    KeLowerIrql(OldIrql);

    KeRevertToUserAffinityThread();

    return TRUE;
}

/// <summary>
/// Assembly function VMXSaveState calls this function.
/// </summary>
VOID LaunchVm(int ProcessorID, EPT_POINTER* EPTP, PVOID GuestStack)
{
    DbgPrint("\n======================== Launching VM =============================\n");
    DbgPrint("[hypoo]\t\tCurrent thread is executing in logical processor: %d \n", ProcessorID);

    DbgPrint("[hypoo] Setting up VMCS...");

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

    // Setup the VMCS data
    SetupVmcs(&g_GuestState[ProcessorID], EPTP, GuestStack);

    DbgPrint("[hypoo] Executing VMLAUNCH");

    INT32 Status = __vmx_vmlaunch();

    if (Status != 0)
    {
        unsigned __int32 VMXError;
        __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &VMXError);
        //__vmx_vmread(0xfffffffe, &VMXError); VMCS_LAUNCH_STATE_FIELD_ENCODING, for auditor
        DbgPrint("[hypoo] VMLAUNCH Failed! VMLAUNCH returned [%d], VMX Error: 0x%0x", Status, VMXError);
    }

    // TODO: Returning is not needed
    return TRUE;

ErrorReturn:
    DbgPrint("[*] Fail to setup VMCS !\n");
    return FALSE;
}

VOID TerminateVmx()
{
    DbgPrint("\n[hypoo] Terminating VMX...\n");

    //int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

    int LogicalProcessorsCount = 1; // test purposes

    for (size_t i = 0; i < LogicalProcessorsCount; i++)
    {
        DbgPrint("\t\t + Terminating VMX on processor %d\n", i);

        TerminateVMXOnProcessor(i);

        //
        // Free the destination memory
        //
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
        ExFreePoolWithTag(g_GuestState[i].VmmStack, POOLTAG);
        ExFreePoolWithTag(g_GuestState[i].MsrBitmap, POOLTAG);
    }

    DbgPrint("[*] VMX terminated successfully. \n");
}

BOOLEAN TerminateVMXOnProcessor(ULONG ProcessorNumber)
{
    KIRQL OldIrql;
    INT32 CpuInfo[4];

    KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

    OldIrql = KeRaiseIrqlToDpcLevel();

    //
    // Our routine is VMXOFF
    //
    __cpuidex(CpuInfo, 0x41414141, 0x42424242);

    KeLowerIrql(OldIrql);

    KeRevertToUserAffinityThread();

    return TRUE;
}

BOOLEAN MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    BOOLEAN Status = FALSE;

    UINT32 ExitReason = 0;
    __vmx_vmread(VMCS_EXIT_REASON, &ExitReason);

    UINT32 ExitQualification = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &ExitQualification);

    DbgPrint("\nVMCS_EXIT_REASION: 0x%x\n", ExitReason);
    DbgPrint("\VMCS_EXIT_QUALIFICATION: 0x%x\n", ExitQualification);

    //ExitReason &= 0xFFFF;

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
        DbgPrint("[hypoo][VMEXIT] Execution of vmlaunch detected... \n");
        ULONG RFLAGS = 0;
        __vmx_vmread(VMCS_GUEST_RFLAGS, &RFLAGS);
        __vmx_vmwrite(VMCS_GUEST_RFLAGS, RFLAGS | 0x1); // cf=1 indicate vm instructions fail

        break;
    }
    case VMX_EXIT_REASON_EXECUTE_HLT:
    {
        break;
    }
    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    {
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_CPUID:
    {
        DbgPrint("[hypoo][VMEXIT] Execution of cpuid detected... \n");

        Status = HandleCPUID(GuestRegs); // Detect whether we have to turn off VMX or Not

        if (Status)
        {
            // We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly

            ULONG ExitInstructionLength = 0;
            g_GuestRIP = 0;
            g_GuestRSP = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &g_GuestRIP);
            __vmx_vmread(VMCS_GUEST_RSP, &g_GuestRSP);
            __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitInstructionLength);

            g_GuestRIP += ExitInstructionLength;
        }

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

    case VMX_EXIT_REASON_EXECUTE_IO_INSTRUCTION:
    {
        UINT64 RIP = 0;
        __vmx_vmread(VMCS_GUEST_RIP, &RIP);

        DbgPrint("[*] RIP executed IO instruction : 0x%llx\n", RIP);

        DbgBreakPoint();

        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDMSR:
    {
        ULONG ECX = GuestRegs->rcx & 0xffffffff;

        // DbgPrint("[*] RDMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRRead(GuestRegs);

        break;
    }

    case VMX_EXIT_REASON_EXECUTE_WRMSR:
    {
        ULONG ECX = GuestRegs->rcx & 0xffffffff;

        // DbgPrint("[*] WRMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRWrite(GuestRegs);

        break;
    }

    case VMX_EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    /* now VMX_EXIT_REASON_PAUSE ?
    case EXIT_REASON_CR_ACCESS:
    {
        HandleControlRegisterAccess(GuestRegs);
        break;
    }
    */

    default:
    {
        DbgPrint("[hypoo][VMEXIT] Execution of unhandled vmexit... \n");
        DbgBreakPoint();
        break;
    }
    }

    if (!Status)
    {
        ResumeToNextInstruction();
    }

    return Status;
}

BOOLEAN HandleCPUID(PGUEST_REGS state)
{
    INT32 CpuInfo[4];
    ULONG Mode = 0;

    //
    // Check for the magic CPUID sequence, and check that it is coming from
    // Ring 0. Technically we could also check the RIP and see if this falls
    // in the expected function, but we may want to allow a separate "unload"
    // driver or code at some point
    //

    __vmx_vmread(VMCS_GUEST_CS_SELECTOR, &Mode);
    Mode = Mode & RPL_MASK;

    if ((state->rax == 0x41414141) && (state->rcx == 0x42424242) && Mode == DPL_SYSTEM)
    {
        return TRUE; // Indicates we have to turn off VMX
    }

    //
    // Otherwise, issue the CPUID to the logical processor based on the indexes
    // on the VP's GPRs
    //
    __cpuidex(CpuInfo, (INT32)state->rax, (INT32)state->rcx);

    //
    // Check if this was CPUID 1h, which is the features request
    //
    if (state->rax == 1)
    {
        //
        // Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication
        //
        CpuInfo[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
    }

    else if (state->rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // Return our interface identifier
        //
        CpuInfo[0] = 'HVFS'; // [H]yper[V]isor [F]rom [S]cratch
    }

    //
    // Copy the values from the logical processor registers into the VP GPRs
    //
    state->rax = CpuInfo[0];
    state->rbx = CpuInfo[1];
    state->rcx = CpuInfo[2];
    state->rdx = CpuInfo[3];

    return FALSE; // Indicates we don't have to turn off VMX
}

VOID HandleControlRegisterAccess(PGUEST_REGS GuestState)
{
    ULONG ExitQualification = 0;

    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &ExitQualification);

    VMX_EXIT_QUALIFICATION_MOV_CR data = { 0 };

    data.AsUInt = &ExitQualification;

    PULONG64 RegPtr = (PULONG64)&GuestState->rax + data.ControlRegister;

    //
    // Because its RSP and as we didn't save RSP correctly (because of pushes)
    // so we have to make it points to the GUEST_RSP
    //
    if (data.ControlRegister == 4)
    {
        INT64 RSP = 0;
        __vmx_vmread(VMCS_GUEST_RSP, &RSP);
        *RegPtr = RSP;
    }

    switch (data.AccessType)
    {
    case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:
    {
        switch (data.ControlRegister)
        {
        case 0:
            __vmx_vmwrite(VMCS_GUEST_CR0, *RegPtr);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, *RegPtr);
            break;
        case 3:

            __vmx_vmwrite(VMCS_GUEST_CR3, (*RegPtr & ~(1ULL << 63)));

            //
            // In the case of using EPT, the context of EPT/VPID should be
            // invalidated
            //
            break;
        case 4:
            __vmx_vmwrite(VMCS_GUEST_CR4, *RegPtr);
            __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, *RegPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data.ControlRegister);
            break;
        }
    }
    break;

    case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:
    {
        switch (data.ControlRegister)
        {
        case 0:
            __vmx_vmread(VMCS_GUEST_CR0, RegPtr);
            break;
        case 3:
            __vmx_vmread(VMCS_GUEST_CR3, RegPtr);
            break;
        case 4:
            __vmx_vmread(VMCS_GUEST_CR4, RegPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data.ControlRegister);
            break;
        }
    }
    break;

    default:
        DbgPrint("[*] Unsupported operation %d\n", data.AccessType);
        break;
    }
}

VOID HandleMSRRead(PGUEST_REGS GuestRegs)
{
    MSR msr = { 0 };

    //
    // RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
    //
    // The "use MSR bitmaps" VM-execution control is 0.
    // The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
    // The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
    //   where n is the value of ECX.
    // The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
    //   where n is the value of ECX & 00001FFFH.
    //

    if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {
        msr.Content = MSRRead((ULONG)GuestRegs->rcx);
    }
    else
    {
        msr.Content = 0;
    }

    GuestRegs->rax = msr.Low;
    GuestRegs->rdx = msr.High;
}

VOID HandleMSRWrite(PGUEST_REGS GuestRegs)
{
    MSR msr = { 0 };

    //
    // Check for the sanity of MSR
    //
    if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {
        msr.Low = (ULONG)GuestRegs->rax;
        msr.High = (ULONG)GuestRegs->rdx;
        MSRWrite((ULONG)GuestRegs->rcx, msr.Content);
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

    UINT32 ErrorCode = 0;

    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();

    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go!
    // prefer to break
    //
    DbgBreakPoint();
}
