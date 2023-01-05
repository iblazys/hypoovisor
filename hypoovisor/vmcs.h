#pragma once
#include "hypoovisor.h"

// temp, will move this once I learn more
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
BOOLEAN SetupVmcs(VIRTUAL_MACHINE_STATE* GuestState, EPT_POINTER* EPTP);

UINT64 GetSegmentBase(UINT64 GdtBase, UINT16 SegmentSelector);
UINT32 ReadSegmentAccessRights(UINT16 SegmentSelector);

ULONG AdjustControls(ULONG CTL_CODE, ULONG Msr);
