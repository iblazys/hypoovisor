#include "hvroutines.h"
#include "hypoovisor.h"
#include "ept.h"
#include "vmstate.h"
#include "shared.h"
#include "dpc.h"
#include "memory.h"
#include "vmcall.h"

BOOLEAN HvVmxInitialize()
{
	int LogicalProcessorsCount = 0;

	// Initialize VMX and EPT
	if (!InitializeHV())
	{
		return FALSE;
	}

	LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

	for (size_t ProcessorID = 0; ProcessorID < LogicalProcessorsCount; ProcessorID++)
	{
		/*** Launching VM for Test (in the all logical processor) ***/

		g_GuestState[ProcessorID].VmmStack = AllocateVMMStack();
		g_GuestState[ProcessorID].MsrBitmapVirtualAddress = AllocateMSRBitmap();
		g_GuestState[ProcessorID].MsrBitmapPhysicalAddress = VirtualToPhysicalAddress(g_GuestState[ProcessorID].MsrBitmapVirtualAddress);

		if (!g_GuestState[ProcessorID].VmmStack || !g_GuestState[ProcessorID].MsrBitmapVirtualAddress)
		{
			// Error is recorded in previous functions.
			return FALSE;
		}

		InitiateCr3 = __readcr3();

		// Let windows execute our routine for us, this eventually calls vmlaunch
		KeGenericCallDpc(HvDpcBroadcastAsmVMXSaveState, 0x0);

		//  Check if everything is ok then return true otherwise false
		if (AsmVmxVmcall(VMCALL_TEST, 0x22, 0x333, 0x4444) == STATUS_SUCCESS)
		{
			///////////////// Test Hook after Vmx is launched /////////////////
			//EptPageHook(ExAllocatePoolWithTag, TRUE);
			///////////////////////////////////////////////////////////////////
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}

	return TRUE;
}

VOID HvDpcBroadcastAsmVMXSaveState(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	// Save the vmx state and prepare vmcs setup and finally execute vmlaunch instruction
	AsmVMXSaveState();

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);
}

/// <summary>
/// Enables vmx on the current processor and allocates vm regions
/// </summary>
/// <returns></returns>
BOOLEAN HvDpcBroadcastAllocateVMRegions(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	INT CurrentProcessorNumber = KeGetCurrentProcessorNumber();

	DbgPrint("=====================================================");

	DbgPrint("[hypoo] Current thread is executing in logical processor: %d", CurrentProcessorNumber);

	AsmEnableVmxOperation(); // lets move this into C eventually?

	DbgPrint("[hypoo] VMX Operation Enabled Successfully !");

	if (!AllocateVMRegion(REGION_VMXON, &g_GuestState[CurrentProcessorNumber]))
		return FALSE;

	if (!AllocateVMRegion(REGION_VMCS, &g_GuestState[CurrentProcessorNumber]))
		return FALSE;

	DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[CurrentProcessorNumber].VmcsRegionVirtualAddress);
	DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[CurrentProcessorNumber].VmxonRegionVirtualAddress);

	DbgPrint("\n=====================================================\n");

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);

	return TRUE;
}

VOID HvTerminateVmx()
{
	// Broadcast to terminate Vmx
	KeGenericCallDpc(HvDpcBroadcastTerminateVmx, 0x0);

	DbgPrint("HvTerminateVmx: KeGenericCallDpc returned.");
	/* De-allocatee global variables */

	// TODO: Enable this, was causing crashes during testing cause ept wasnt set up.
	
	/*
	// Free each split 
	FOR_EACH_LIST_ENTRY(g_EptState->EptPageTable, DynamicSplitList, VMM_EPT_DYNAMIC_SPLIT, Split)
		ExFreePoolWithTag(Split, POOLTAG);
	FOR_EACH_LIST_ENTRY_END();

	// Free Identity Page Table
	MmFreeContiguousMemory(g_EptState->EptPageTable);
	*/

	// Free GuestState
	ExFreePoolWithTag(g_GuestState, POOLTAG);
	DbgPrint("HvTerminateVmx: Free guest state");

	// Free EptState
	ExFreePoolWithTag(g_EptState, POOLTAG);
}

VOID HvDpcBroadcastTerminateVmx(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	int CurrentProcessorIndex = KeGetCurrentProcessorNumber();

	// Terminate Vmx using Vmcall
	if (!VMXTerminate())
	{
		LogError("There was an error terminating Vmx");
		DbgBreakPoint();
	}

	//LogInfo("VMXTerminate was successful on logical core %d. Now waiting for other processors.", CurrentProcessorIndex);

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);

	//LogInfo("DPCs synchronized and complete");

	//DbgPrint("KeSignalCallDpcDone returned.");
}

VOID HvHandleCPUID(PGUEST_REGS RegistersState)
{
	INT32 cpu_info[4];
	ULONG Mode = 0;

	// Check for the magic CPUID sequence, and check that it is coming from
	// Ring 0. Technically we could also check the RIP and see if this falls
	// in the expected function, but we may want to allow a separate "unload"
	// driver or code at some point.

	/***  It's better to turn off hypervisor from Vmcall ***/
	/*
	__vmx_vmread(GUEST_CS_SELECTOR, &Mode);
	Mode = Mode & RPL_MASK;
	if ((RegistersState->rax == 0x41414141) && (RegistersState->rcx == 0x42424242) && Mode == DPL_SYSTEM)
	{
		return TRUE; // Indicates we have to turn off VMX
	}
	*/

	// Otherwise, issue the CPUID to the logical processor based on the indexes
	// on the VP's GPRs.
	__cpuidex(cpu_info, (INT32)RegistersState->rax, (INT32)RegistersState->rcx);

	// Check if this was CPUID 1h, which is the features request.
	if (RegistersState->rax == 1)
	{

		// Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
		// reserved for this indication.
		cpu_info[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
	}

	else if (RegistersState->rax == HYPERV_CPUID_INTERFACE)
	{
		// Return our interface identifier
		cpu_info[0] = 'HVFS'; // TODO: Change me [H]yper[v]isor [F]rom [S]cratch 
	}

	// Copy the values from the logical processor registers into the VP GPRs.
	RegistersState->rax = cpu_info[0];
	RegistersState->rbx = cpu_info[1];
	RegistersState->rcx = cpu_info[2];
	RegistersState->rdx = cpu_info[3];
}

VOID HvHandleControlRegisterAccess(PGUEST_REGS GuestState)
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

VOID HvRestoreRegisters()
{
	ULONG64 FsBase;
	ULONG64 GsBase;
	ULONG64 GdtrBase;
	ULONG64 GdtrLimit;
	ULONG64 IdtrBase;
	ULONG64 IdtrLimit;

	// Restore FS Base 
	__vmx_vmread(VMCS_GUEST_FS_BASE, &FsBase);
	__writemsr(IA32_FS_BASE, FsBase);

	// Restore Gs Base
	__vmx_vmread(VMCS_GUEST_GS_BASE, &GsBase);
	__writemsr(IA32_GS_BASE, GsBase);

	// Restore GDTR
	__vmx_vmread(VMCS_GUEST_GDTR_BASE, &GdtrBase);
	__vmx_vmread(VMCS_GUEST_GDTR_LIMIT, &GdtrLimit);

	AsmReloadGdtr(GdtrBase, GdtrLimit);

	// Restore IDTR
	__vmx_vmread(VMCS_GUEST_IDTR_BASE, &IdtrBase);
	__vmx_vmread(VMCS_GUEST_IDTR_LIMIT, &IdtrLimit);

	AsmReloadIdtr(IdtrBase, IdtrLimit);
}

UINT64 HvReturnStackPointerForVmxoff()
{
	return g_GuestState[KeGetCurrentProcessorNumber()].VmxoffState.GuestRsp;
}

UINT64 HvReturnInstructionPointerForVmxoff()
{
	return g_GuestState[KeGetCurrentProcessorNumber()].VmxoffState.GuestRip;
}
