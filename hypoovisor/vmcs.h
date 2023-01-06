#pragma once
#include "hypoovisor.h"

// wont need this soon
typedef union _MSR
{
    struct
    {
        ULONG Low;
        ULONG High;
    };

    ULONG64 Content;
} MSR, * PMSR;

#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_CTL2_RDTSCP   0x8

#define VM_ENTRY_IA32E_MODE         0x00000200
#define VM_EXIT_IA32E_MODE          0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT    0x00008000


UINT64 VmptrstInstruction();
BOOLEAN ClearVmcsState(VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN LoadVmcs(VIRTUAL_MACHINE_STATE* GuestState);

BOOLEAN SetupVmcs(VIRTUAL_MACHINE_STATE* GuestState, EPT_POINTER* EPTP); // rewriting

// remove data in namings perhaps
VOID SetupVmcsControlData();
VOID SetupVmcsGuestData(SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr, SEGMENT_DESCRIPTOR_REGISTER_64* Idtr);
VOID SetupVmcsHostData(SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr, SEGMENT_DESCRIPTOR_REGISTER_64* Idtr);

VOID SetEntryControls(IA32_VMX_ENTRY_CTLS_REGISTER* EntryControls);
VOID SetExitControls(IA32_VMX_EXIT_CTLS_REGISTER* ExitControls);
VOID SetPinbasedControls(IA32_VMX_PINBASED_CTLS_REGISTER* PinbasedControls);
VOID SetProcbasedControls(IA32_VMX_PROCBASED_CTLS_REGISTER* ProcbasedControls);
VOID SetSecondaryControls(IA32_VMX_PROCBASED_CTLS2_REGISTER* SecondaryControls);

IA32_VMX_BASIC_REGISTER GetBasicControls();
VOID AdjustControl(UINT32 CapabilityMSR, UINT32* Value);

VOID DebugVmcs(SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr, SEGMENT_DESCRIPTOR_REGISTER_64* Idtr);

UINT64 GetSegmentBase(UINT64 GdtBase, UINT16 SegmentSelector);
UINT32 ReadSegmentAccessRights(UINT16 SegmentSelector);
ULONG AdjustControls(ULONG CapabilityMSR, ULONG Value);
