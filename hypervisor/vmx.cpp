#include <intrin.h>

#include "vmx.h"
#include "msr.h"
#include "utils.h"
#include "mem.h"

extern "C" void AsmEnableVmxOperation(void);

namespace vmx {

    VIRTUAL_MACHINE_STATE* g_GuestState;
    int  g_ProcessorCounts;

    BOOLEAN InitializeVmx()
    {
        if (!IsVMXSupported())
        {
            DbgPrint("[*] VMX is not supported in this machine !");
            return FALSE;
        }

        g_ProcessorCounts = KeQueryActiveProcessorCount(0);
        g_GuestState = (VIRTUAL_MACHINE_STATE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * g_ProcessorCounts, POOLTAG);

        DbgPrint("\n=====================================================\n");

        KAFFINITY AffinityMask;
        for (size_t i = 0; i < g_ProcessorCounts; i++)
        {
            AffinityMask = MathPower(2, i);

            KeSetSystemAffinityThread(AffinityMask);

            DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

            //
            // Enabling VMX Operation
            //
            AsmEnableVmxOperation();

            DbgPrint("[*] VMX Operation Enabled Successfully !");

            mem::AllocateVmxonRegion(&g_GuestState[i]);
            mem::AllocateVmcsRegion(&g_GuestState[i]);

            DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[i].VmcsRegion);
            DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[i].VmxonRegion);

            DbgPrint("\n=====================================================\n");
        }

        return TRUE;
    }

    BOOLEAN IsVMXSupported()
    {
        CPUID Data = { 0 };

        //
        // Check for the VMX bit
        //
        __cpuid((int*)&Data, 1);
        if ((Data.ecx & (1 << 5)) == 0)
            return FALSE;

        IA32_FEATURE_CONTROL_MSR Control = { 0 };
        Control.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

        //
        // BIOS lock check
        //
        if (Control.Fields.Lock == 0)
        {
            Control.Fields.Lock = TRUE;
            Control.Fields.EnableVmxon = TRUE;
            __writemsr(MSR_IA32_FEATURE_CONTROL, Control.All); // check MSR address 0x3A for the lock bit
        }
        else if (Control.Fields.EnableVmxon == FALSE)
        {
            // this usually means a hypervisor is already running.
            DbgPrint("[*] VMX locked off in BIOS");
            return FALSE;
        }

        return TRUE;
    }

    VOID TerminateVmx()
    {
        DbgPrint("\n[*] Terminating VMX...\n");

        KAFFINITY AffinityMask;
        for (size_t i = 0; i < g_ProcessorCounts; i++)
        {
            AffinityMask = MathPower(2, i);
            KeSetSystemAffinityThread(AffinityMask);
            DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

            __vmx_off();
            MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
            MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
        }

        DbgPrint("[*] VMX Operation turned off successfully. \n");
    }
}
