#ifndef VMSTATE_H
#define VMSTATE_H

#include <ntddk.h>

// Globals

VIRTUAL_MACHINE_STATE *g_GuestState;
EPT_STATE *g_EptState;

// Because we may be executing in an arbitrary user-mode 
// process as part of the DPC interrupt we execute in
// We have to save Cr3, for HOST_CR3
UINT64 InitiateCr3;

#endif