#pragma once
#include <ntddk.h>

// This file is essentially our VMM - Virtual Machine Manager
#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096

#define POOLTAG 0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS) - Change ME

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion; // VMXON region
    UINT64 VmcsRegion;  // VMCS region
} VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

extern VIRTUAL_MACHINE_STATE *g_GuestState;
extern int g_ProcessorCounts;
extern void inline AsmEnableVmxOperation(void);

BOOLEAN InitializeHV();
BOOLEAN StopHV();

BOOLEAN AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN AllocateVmcsRegion(IN VIRTUAL_MACHINE_STATE* GuestState);
VOID TerminateVmx();

