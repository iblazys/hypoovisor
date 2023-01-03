#include "hypervisor.h"
#include <ntddk.h>
#include "utils.h"

bool Init() 
{
    // Check VMX support etc

    return false;
}

bool Start() 
{
    KAFFINITY AffinityMask;
    for (size_t i = 0; i < KeQueryActiveProcessors(); i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);

        DbgPrint("=====================================================");
        DbgPrint("Current thread is executing in %d th logical processor.", i);

        // run code here for each processor

    }

    return false;
}
