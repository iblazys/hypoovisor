#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <ntddk.h>

//
// Contains functions that will allow the hypervisor to run on multiple cpu's.
// 

BOOLEAN IsVMXSupported();

/**
 * Get an MSR by its address and convert it to the specified type.
 */
SIZE_T GetHostMSR(ULONG MsrAddress);

UINT32 GetCPUIDRegister(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister);
BOOLEAN IsCPUFeaturePresent(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister, INT32 FeatureBit);

//BOOLEAN IsVMXAvailable();

#endif
