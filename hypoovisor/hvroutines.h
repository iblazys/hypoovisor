#ifndef HVROUTINES_H
#define HVROUTINES_H

#include <ntddk.h>
#include "shared.h"

BOOLEAN HvVmxInitialize();

VOID HvDpcBroadcastAsmVMXSaveState(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

BOOLEAN HvDpcBroadcastAllocateVMRegions(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

/* Terminate Vmx on all logical cores. */
VOID HvTerminateVmx();
VOID HvDpcBroadcastTerminateVmx(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

VOID HvHandleCPUID(PGUEST_REGS RegistersState);
VOID HvHandleControlRegisterAccess(PGUEST_REGS GuestState);

VOID HvRestoreRegisters();

UINT64 HvReturnStackPointerForVmxoff();
UINT64 HvReturnInstructionPointerForVmxoff();

#endif