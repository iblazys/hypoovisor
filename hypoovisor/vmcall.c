#include "vmcall.h"
#include "hypoovisor.h"
#include "ept.h"

NTSTATUS VMXVmcallHandler(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
{
    NTSTATUS VmcallStatus;
    BOOLEAN HookResult;

    VmcallStatus = STATUS_UNSUCCESSFUL;

    switch (VmcallNumber)
    {

    case VMCALL_TEST:
    {
        VmcallStatus = VmcallTest(OptionalParam1, OptionalParam2, OptionalParam3);
        break;
    }

    case VMCALL_VMXOFF:
    {
        /*
            [+] Information (DrvClose:49) |  Stopping hypoovisor and terminating VMX.
            [+] Information (VMXTerminate:164) |  Terminating VMX on logical core 0
            [+] Information (VMXTerminate:164) |  Terminating VMX on logical core 3
            [+] Information (VMXTerminate:164) |  Terminating VMX on logical core 2
            [+] Information (VMXTerminate:164) |  Terminating VMX on logical core 1
            [+] Information (VMXTerminate:164) |  Terminating VMX on logical core 4
            [+] Information (VMXTerminate:172) |  VMX termination was successful on logical core 0
            [+] Information (VMXTerminate:172) | 	VMX termination was successful on logical core 1
            [+] Information (VMXTerminate:172) | 	VMX termination was successful on logical core 4
            Access violation - code c0000005 (!!! second chance !!!)
            nt_exe!KiSaveProcessorControlState+0x171:
            fffff805`14a09461 c3              ret

            Also getting invalid vmcalls, instant shutdowns, etc
        */

        VMXVmxOff();

        VmcallStatus = STATUS_SUCCESS;
        break;
    }

    case VMCALL_EXEC_HOOK_PAGE:
    {
        HookResult = EptVmxRootModePageHook(OptionalParam1, TRUE);

        if (HookResult)
        {
            VmcallStatus = STATUS_SUCCESS;
        }
        else
        {
            VmcallStatus = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    
    case VMCALL_INVEPT_SINGLE_CONTEXT:
    {
        InveptSingleContexts(OptionalParam1);

        VmcallStatus = STATUS_SUCCESS;
        break;
    }

    case VMCALL_INVEPT_ALL_CONTEXT:
    {
        InveptAllContexts();

        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    
    default:
    {
        DbgBreakPoint();
        LogWarning("Unsupported VMCALL, VMCallNumber: %d", VmcallNumber);
        VmcallStatus = STATUS_UNSUCCESSFUL;
        break;
    }
    }

    return VmcallStatus;
}

NTSTATUS VmcallTest(UINT64 Param1, UINT64 Param2, UINT64 Param3) {

    LogInfo("VmcallTest called with @Param1 = 0x%llx , @Param2 = 0x%llx , @Param3 = 0x%llx", Param1, Param2, Param3);
    return STATUS_SUCCESS;
}