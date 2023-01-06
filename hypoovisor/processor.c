#include "processor.h"

#include <ia32.h>
#include "intrin.h"
#include "utils.h"

BOOLEAN IsVMXSupported()
{
    CPUID_EAX_01 Data = { 0 };
    
    //
    // Check for the VMX bit
    //
    __cpuid((int*)&Data, 1);

    if (Data.CpuidFeatureInformationEcx.VirtualMachineExtensions == 0)
        return FALSE;

    IA32_FEATURE_CONTROL_REGISTER Control = { 0 };
    Control.AsUInt = GetHostMSR(IA32_FEATURE_CONTROL);

    // BIOS lock checking
    if (Control.LockBit == 0) // Check if lock exists
    {
        Control.LockBit = TRUE;
        Control.EnableVmxInsideSmx = TRUE; // should we eventually be setting EnableVmxOutsideSmx to false ?

        // Write the MSR with lock bit set to 1 and EnableVmxInsideSmx to 1
        __writemsr(IA32_FEATURE_CONTROL, Control.AsUInt);
    }
    else if (Control.EnableVmxOutsideSmx == FALSE)
    {
        DbgPrint("[*] VMX locked off in BIOS");
        return FALSE;
    }

    return TRUE;
}

SIZE_T GetHostMSR(ULONG MsrAddress)
{
    return __readmsr(MsrAddress);
}

/// <summary>
/// 
/// </summary>
UINT32 GetCPUIDRegister(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister) 
{
    INT32 CPUInfo[4];

    __cpuidex(CPUInfo, FunctionId, SubFunctionId);

    return (UINT32)CPUInfo[CPUIDRegister];
}

BOOLEAN IsCPUFeaturePresent(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister, INT32 FeatureBit)
{
    UINT32 Register;

    Register = GetCPUIDRegister(FunctionId, SubFunctionId, CPUIDRegister);

    return IsBitSet(Register, FeatureBit);
}

/*
BOOLEAN ArchIsVMXAvailable()
{
    return IsCPUFeaturePresent(CPUID_VMX_ENABLED_FUNCTION,
        CPUID_VMX_ENABLED_SUBFUNCTION,
        CPUID_ECX,
        CPUID_FEATURE_INFORMATION_ECX_VIRTUAL_MACHINE_EXTENSIONS_BIT);
}
*/
