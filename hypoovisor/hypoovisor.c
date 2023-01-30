#include "hypoovisor.h"
#include "shared.h"
#include "ept.h"
#include "vmstate.h"
#include "vmcs.h"
#include "vmcall.h"
#include "hvroutines.h"
#include "processor.h"
#include "utils.h"
#include "memory.h"
#include "dpc.h"

#include <windef.h> // for BYTE*

//VIRTUAL_MACHINE_STATE *g_GuestState;
UINT64 g_VirtualGuestMemoryAddress; // remove me

/// <summary>
/// Check processor support features and initialize VMX/EPT.
/// </summary>
/// <returns></returns>
BOOLEAN InitializeHV()
{
    INT ProcessorCount = 0;
    
	DbgPrint("[hypoo] Hypoovisor initializing...");

    // TODO: Check EPT Support, g_VirtualGuestMemoryAddress gets its address from here.
    //EPT_POINTER* EPTp = InitializeEptPointer();

    if (!IsVMXSupported()) 
    {
        DbgPrint("[hypoo] VMX is not supported on this processor.");
        return FALSE;
    }

    PAGED_CODE();

    ProcessorCount = KeQueryActiveProcessorCount(0);

    // Allocate and zero guest state
    g_GuestState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCount, POOLTAG);
    RtlZeroMemory(g_GuestState, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCount);

    // Allocate	and zero ept state
    g_EptState = ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_STATE), POOLTAG);
    RtlZeroMemory(g_EptState, sizeof(EPT_STATE));

    // TODO: EPT Stuff

    //g_GuestState->Eptp = EPTp;

    // Allocate and run vmxon and vmptrld on 
    KeGenericCallDpc(HvDpcBroadcastAllocateVMRegions, 0x0);

	return TRUE;
}

/// <summary>
/// 
/// </summary>
/// <returns></returns>
BOOLEAN StopHV() 
{
    HvTerminateVmx();

    LogInfo("Hypoovisor stopped and VMX terminated successfully.");

    return TRUE;
}

VOID FixCr4AndCr0Bits()
{
    CR_FIXED CrFixed = { 0 };
    CR4      Cr4 = { 0 };
    CR0      Cr0 = { 0 };

    //
    // Fix Cr0
    //
    CrFixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
    Cr0.AsUInt = __readcr0();
    Cr0.AsUInt |= CrFixed.Fields.Low;
    CrFixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
    Cr0.AsUInt &= CrFixed.Fields.Low;
    __writecr0(Cr0.AsUInt);

    //
    // Fix Cr4
    //
    CrFixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
    Cr4.AsUInt = __readcr4();
    Cr4.AsUInt |= CrFixed.Fields.Low;
    CrFixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
    Cr4.AsUInt &= CrFixed.Fields.Low;
    __writecr4(Cr4.AsUInt);
}

/// <summary>
/// Assembly function AsmVMXSaveState calls this function.
/// </summary>
BOOLEAN LaunchVm(PVOID GuestStack)
{
    // TODO: More error checking

    INT ProcessorID = 0;

    ProcessorID = KeGetCurrentProcessorNumber();

    DbgPrint("\n======================== Launching VM  (Logical Core : 0x%x) =============================", ProcessorID);

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
    SetupVmcs(&g_GuestState[ProcessorID], GuestStack);

    DbgPrint("[hypoo] Executing VMLAUNCH");

    INT32 Status = __vmx_vmlaunch();

    if (Status != 0)
    {
        unsigned __int32 VMXError;
        __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &VMXError);
        __vmx_off();
        DbgPrint("[hypoo] VMLAUNCH Failed! VMLAUNCH returned [%d], VMX Error: 0x%0x", Status, VMXError);
    }

    return FALSE;

ErrorReturn:
    DbgPrint("[*] Fail to setup VMCS !\n");
    return FALSE;
}



/// <summary>
/// Terminates VMX via VMCALL
/// </summary>
/// <returns></returns>
BOOLEAN VMXTerminate()
{
    int CurrentCoreIndex;
    NTSTATUS Status;

    // Get the current core index
    CurrentCoreIndex = KeGetCurrentProcessorNumber();

    LogInfo("\tTerminating VMX on logical core %d", CurrentCoreIndex);

    //ASSERT(g_GuestState != NULL && "Guest state already freed on current processor!");
    //ASSERT(g_GuestState->VmxoffState.IsVmxoffExecuted == TRUE && "VMX already turned off on current processor!");

    // Execute Vmcall to to turn off vmx from Vmx root mode
    Status = AsmVmxVmcall(VMCALL_VMXOFF, NULL, NULL, NULL);

    if (Status == STATUS_SUCCESS)
    {
        // Still in root mode, risky af
        LogInfo("\tVMX termination was successful on logical core %d", CurrentCoreIndex);

        // Free the destination memory
        MmFreeContiguousMemory(g_GuestState[CurrentCoreIndex].VmxonRegionVirtualAddress);
        MmFreeContiguousMemory(g_GuestState[CurrentCoreIndex].VmcsRegionVirtualAddress);

        if(g_GuestState[CurrentCoreIndex].VmmStack)
            ExFreePoolWithTag(g_GuestState[CurrentCoreIndex].VmmStack, POOLTAG);

        if(g_GuestState[CurrentCoreIndex].MsrBitmapVirtualAddress)
            ExFreePoolWithTag(g_GuestState[CurrentCoreIndex].MsrBitmapVirtualAddress, POOLTAG);

        // TEST ASSERT
        ASSERT(g_GuestState[CurrentCoreIndex].VmmStack != NULL);

        // Still in root mode, risky af
        //LogInfo("\tFreed GuestState members on logical core %d", CurrentCoreIndex);

        return TRUE;
    }

    return FALSE;
}

VOID VMXVmxOff()
{
    int CurrentProcessorIndex;
    UINT64 GuestRSP; 	// Save a pointer to guest rsp for times that we want to return to previous guest stateS
    UINT64 GuestRIP; 	// Save a pointer to guest rip for times that we want to return to previous guest state
    UINT64 GuestCr3;
    UINT64 ExitInstructionLength;


    // Initialize the variables
    ExitInstructionLength = 0;
    GuestRIP = 0;
    GuestRSP = 0;

    CurrentProcessorIndex = KeGetCurrentProcessorNumber();

    //LogInfo("attempting vmx_off on logical core %d", CurrentProcessorIndex);

    /*
    According to SimpleVisor :
        Our callback routine may have interrupted an arbitrary user process,
        and therefore not a thread running with a system-wide page directory.
        Therefore if we return back to the original caller after turning off
        VMX, it will keep our current "host" CR3 value which we set on entry
        to the PML4 of the SYSTEM process. We want to return back with the
        correct value of the "guest" CR3, so that the currently executing
        process continues to run with its expected address space mappings.
    */

    UINT64 HOST = InitiateCr3;

    __vmx_vmread(VMCS_GUEST_CR3, &GuestCr3);
    __writecr3(GuestCr3);

    // Read guest rsp and rip
    __vmx_vmread(VMCS_GUEST_RIP, &GuestRIP);
    __vmx_vmread(VMCS_GUEST_RSP, &GuestRSP);

    // Read instruction length
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitInstructionLength);
    GuestRIP += ExitInstructionLength;

    // Set the previous registe states
    g_GuestState[CurrentProcessorIndex].VmxoffState.GuestRip = GuestRIP;
    g_GuestState[CurrentProcessorIndex].VmxoffState.GuestRsp = GuestRSP;

    // Notify the Vmexit handler that VMX already turned off
    g_GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted = TRUE;

    // Restore the previous FS, GS , GDTR and IDTR register so patchguard doesnt fuck us down
    HvRestoreRegisters();

    // Execute vmclear - required by intel manual see 24.11.1 vol 3C
    // Doing this causes the system to hang though.... what gives?
    //__vmx_vmclear(g_GuestState[CurrentProcessorIndex].VmcsRegionPhysicalAddress);

    // Execute Vmxoff
    __vmx_off(); // fails here so often -.-, been debugging this forever

    // Disable VM extensions bit in CR4
    DisableVMXe();
}

/* 
* Cant read from the VM when VMXOFF is executed according to intel manual
* But why does this happen? And only sometimes?
* .
[+] Information (VMXTerminate:140) |  Terminating VMX on logical core 1...0...2...4...3.......
[+] Information (VMXTerminate:148) |  VMX termination was successful on logical core 1
[!] Error (MainVmexitHandler:241) | VMEXIT occuring on logical processor with vmxoff already executed.
Unknown exception - code 00000010 (!!! second chance !!!)
hypoovisor!MainVmexitHandler+0xb9:
fffff800`66112a59 0f78442434      vmread  qword ptr [rsp+34h],rax
4: kd> g
[+] Information (VMXTerminate:162) | 	Freed GuestState members on logical core 1
Illegal instruction - code c000001d (!!! second chance !!!)
hypoovisor!MainVmexitHandler+0xb9:
fffff800`66112a59 0f78442434      vmread  qword ptr [rsp+34h],rax

*/

BOOLEAN MainVmexitHandler(PGUEST_REGS GuestRegs)
{    
    BOOLEAN Status = FALSE;
    int CurrentProcessorIndex = 0;
    UINT64 GuestPhysicalAddr = 0;
    UINT64 GuestRip = 0;

    CurrentProcessorIndex = KeGetCurrentProcessorNumber();

    // Check if VMX is already turned off before we start handling this vm exit
    if (g_GuestState[CurrentProcessorIndex].IsOnVmxRootMode == FALSE && g_GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted)
    {
        LogError("VMEXIT occuring on logical processor with vmxoff already executed.");
        return TRUE;
    }

    g_GuestState[CurrentProcessorIndex].IsOnVmxRootMode = TRUE;
    g_GuestState[CurrentProcessorIndex].IncrementRip = TRUE;

    ULONG ExitReason = 0;
    __vmx_vmread(VMCS_EXIT_REASON, &ExitReason); // getting a illegal instruction exception here

    ULONG ExitQualification = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &ExitQualification);

    //DbgPrint("\nVMCS_EXIT_REASION: 0x%x\n", ExitReason);
    //DbgPrint("\VMCS_EXIT_QUALIFICATION: 0x%x\n", ExitQualification);

    ExitReason &= 0xFFFF;

    switch (ExitReason)
    {
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case VMX_EXIT_REASON_TRIPLE_FAULT:
    {
        DbgPrint("TRIPLE FAULT");
        DbgBreakPoint();
        break;
    }

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
        HvHandleCPUID(GuestRegs);

        break;
    }

    case VMX_EXIT_REASON_EXECUTE_INVD:
    {
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_VMCALL:
    {
        GuestRegs->rax = VMXVmcallHandler(GuestRegs->rcx, GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9); // kinda helps if this is here -.-
        break;
    }

    case VMX_EXIT_REASON_MOV_CR:
    {
        HvHandleControlRegisterAccess(GuestRegs);
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
        // Reading guest physical address
        GuestPhysicalAddr = 0;
        __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);
        LogInfo("Guest Physical Address : 0x%llx", GuestPhysicalAddr);

        // Reading guest's RIP 
        GuestRip = 0;
        __vmx_vmread(VMCS_GUEST_RIP, &GuestRip);
        LogInfo("Guest Rip : 0x%llx", GuestRip);

        if (!EptHandleEptViolation(ExitQualification, GuestPhysicalAddr))
        {
            LogError("There were errors in handling Ept Violation");
        }

        break;
    }

    case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
    {
        GuestPhysicalAddr = 0;
        __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);

        EptHandleMisconfiguration(GuestPhysicalAddr);

        break;
    }

    default:
    {
        DbgPrint("[hypoo][VMEXIT] Execution of unhandled vmexit... \n");
        DbgBreakPoint();
        break;
    }
    }

    if (!g_GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted && g_GuestState[CurrentProcessorIndex].IncrementRip)
    {
        ResumeToNextInstruction();
    }

    // Set indicator of Vmx non root mode to false
    g_GuestState[CurrentProcessorIndex].IsOnVmxRootMode = FALSE;

    if (g_GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted)
    {
        return TRUE;
    }

    return FALSE;
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
    ULONG64 ResumeRIP = NULL;
    ULONG64 CurrentRIP = NULL;
    ULONG ExitInstructionLength = 0;

    __vmx_vmread(VMCS_GUEST_RIP, &CurrentRIP);
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitInstructionLength);

    ResumeRIP = CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(VMCS_GUEST_RIP, ResumeRIP);
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

/* Invalidate EPT using Vmcall (should be called from Vmx non root mode) */
VOID HvInvalidateEptByVmcall(UINT64 Context)
{
    if (Context == NULL)
    {
        // We have to invalidate all contexts
        AsmVmxVmcall(VMCALL_INVEPT_ALL_CONTEXT, NULL, NULL, NULL);
    }
    else
    {
        // We have to invalidate all contexts
        AsmVmxVmcall(VMCALL_INVEPT_SINGLE_CONTEXT, Context, NULL, NULL);
    }
}

VOID HvNotifyAllToInvalidateEpt()
{
    // Let's notify them all
    KeIpiGenericCall(HvInvalidateEptByVmcall, g_EptState->EptPointer.AsUInt);
}

//
// TEMPORARY
//

/* Print logs in different levels */
VOID LogPrintInfo(PCSTR Format) {
    DbgPrint(Format);
}
VOID LogPrintWarning(PCSTR Format) {
    DbgPrint(Format);
}
VOID LogPrintError(PCSTR Format) {
    DbgPrint(Format);
}
