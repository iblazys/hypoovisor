#include "vmx.h"
#include "msr.h"
#include <intrin.h>

namespace vmx {
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
            __writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
        }
        else if (Control.Fields.EnableVmxon == FALSE)
        {
            DbgPrint("[*] VMX locked off in BIOS");
            return FALSE;
        }

        return TRUE;
    }
}
