#pragma once

#include <ntddk.h>

BOOLEAN IsVMXSupported();

/**
 * Get an MSR by its address and convert it to the specified type.
 */
SIZE_T GetHostMSR(ULONG MsrAddress);

UINT32 GetCPUIDRegister(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister);
BOOLEAN IsCPUFeaturePresent(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister, INT32 FeatureBit);

//BOOLEAN IsVMXAvailable();

