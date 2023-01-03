#ifndef VMX_H
#define VMX_H
#include <ntddk.h>

namespace vmx 
{
    #define ALIGNMENT_PAGE_SIZE 4096
    #define MAXIMUM_ADDRESS     0xFFFFFFFFFFFFFFFF
    #define VMCS_SIZE           4096
    #define VMXON_SIZE          4096

    typedef struct _VIRTUAL_MACHINE_STATE
    {
        UINT64 VmxonRegion; // VMXON region
        UINT64 VmcsRegion;  // VMCS region
    } VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

    extern VIRTUAL_MACHINE_STATE*   g_GuestState;
    extern int  g_ProcessorCounts;

    #define POOLTAG 0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS) -- CHANGE ME

    BOOLEAN IsVMXSupported();
    BOOLEAN InitializeVmx();
    VOID TerminateVmx();
}
#endif

