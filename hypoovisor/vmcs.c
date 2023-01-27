
#include "vmcs.h"
#include "ept.h"
#include "vmstate.h"

#pragma warning(disable : 6328)

/// <summary>
/// Stores the current-VMCS pointer into a specified memory address.
/// </summary>
/// <returns></returns>
UINT64 VmptrstInstruction()
{
    PHYSICAL_ADDRESS vmcspa;
    vmcspa.QuadPart = 0;
    __vmx_vmptrst((unsigned __int64*)&vmcspa);

    DbgPrint("[*] VMPTRST %llx\n", vmcspa);

    return 0;
}

/// <summary>
/// Clears the state of the current vcpu vmcs region
/// </summary>
BOOLEAN ClearVmcsState(VIRTUAL_MACHINE_STATE* GuestState)
{
    // Clear the state of the VMCS to inactive
    int status = __vmx_vmclear(&GuestState->VmcsRegionPhysicalAddress);

    DbgPrint("[*] VMCS VMCLEAR Status is : %d\n", status);
    if (status)
    {
        // Otherwise, terminate the VMX
        DbgPrint("[*] VMCS failed to clear with status %d\n", status);
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

/// <summary>
/// Marks the current VMCS pointer valid and loads it with the supplied physical address.
/// Fails if the supplied address is not properly alligned.
/// </summary>
BOOLEAN LoadVmcs(VIRTUAL_MACHINE_STATE* GuestState)
{
    int status = __vmx_vmptrld(&GuestState->VmcsRegionPhysicalAddress);
    if (status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", status);
        return FALSE;
    }
    return TRUE;
}
VOID SetupVmcsHostData(SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr, SEGMENT_DESCRIPTOR_REGISTER_64* Idtr)
{
    DbgPrint("[hypoo] Setting up VMCS host data");

    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, GetEs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, GetCs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, GetSs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, GetDs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, GetFs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, GetGs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, GetTr() & 0xF8);

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR3, InitiateCr3/*__readcr3()*/);
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_HOST_TR_BASE, GetSegmentBase(Gdtr->BaseAddress, GetTr()));

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, Gdtr->BaseAddress);
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, Idtr->BaseAddress);
    
    // (((ULONG64)g_GuestState->VmmStack + VMM_STACK_SIZE) & ~0b1111ull) - 8)
    __vmx_vmwrite(VMCS_HOST_RSP, ((ULONG64)g_GuestState->VmmStack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(VMCS_HOST_RIP, (ULONG64)AsmVmexitHandler);

    // DEBUG
    /*
    DbgPrint("host_state.gdtr_base: [0x%02X]", Gdtr->BaseAddress);
    DbgPrint("host_state.gdtr_limit: [0x%02X]", Gdtr->Limit);
    DbgPrint("host_state.idtr_base: [0x%02X]", Idtr->BaseAddress);
    DbgPrint("host_state.idtr_limit: [0x%02X]", Idtr->Limit);
    */
}

VOID SetupVmcsGuestData(SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr, SEGMENT_DESCRIPTOR_REGISTER_64* Idtr, PVOID GuestStack)
{
    DbgPrint("[hypoo] Setting up VMCS guest data");

    // ------------ Segmentation -----------------
    //SEGMENT_DESCRIPTOR_REGISTER_64  Gdtr = { 0 };
    //SEGMENT_DESCRIPTOR_REGISTER_64  Idtr = { 0 };

    // Selectors
    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, GetCs());
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, GetDs());
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, GetEs());
    __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, GetFs());
    __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, GetGs());
    __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, GetSs());
    __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, GetLdtr());
    __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, GetTr());

    // Limits
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, __segmentlimit(GetCs()));
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, __segmentlimit(GetDs()));
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, __segmentlimit(GetEs()));
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, __segmentlimit(GetFs()));
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, __segmentlimit(GetGs()));
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, __segmentlimit(GetSs()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(GetLdtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, __segmentlimit(GetTr()));

    _sgdt(Gdtr);
    __sidt(Idtr);

    /*
    DbgPrint("host_state.gdtr_base: [0x%02X]", Gdtr->BaseAddress);
    DbgPrint("host_state.gdtr_limit: [0x%02X]", Gdtr->Limit);
    DbgPrint("host_state.idtr_base: [0x%02X]", Idtr->BaseAddress);
    DbgPrint("host_state.idtr_limit: [0x%02X]", Idtr->Limit);
    */

    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, Gdtr->Limit);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, Idtr->Limit);
    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, Gdtr->BaseAddress);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, Idtr->BaseAddress);
    
    // Bases
    __vmx_vmwrite(VMCS_GUEST_ES_BASE, GetSegmentBase(Gdtr->BaseAddress, GetEs()));
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, GetSegmentBase(Gdtr->BaseAddress, GetCs()));
    __vmx_vmwrite(VMCS_GUEST_SS_BASE, GetSegmentBase(Gdtr->BaseAddress, GetSs()));
    __vmx_vmwrite(VMCS_GUEST_DS_BASE, GetSegmentBase(Gdtr->BaseAddress, GetDs()));
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, GetSegmentBase(Gdtr->BaseAddress, GetLdtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, GetSegmentBase(Gdtr->BaseAddress, GetTr()));
    
    // Access Rights
    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetCs()));
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetSs()));
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetDs()));
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, ReadSegmentAccessRights(GetEs()));
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetFs()));
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetGs()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, ReadSegmentAccessRights(GetLdtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, ReadSegmentAccessRights(GetTr()));
    // ------------ End Segmentation -----------------

    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL));

    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0); // Active state

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, GetRflags());
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_GUEST_RSP, (ULONG64)GuestStack);
    __vmx_vmwrite(VMCS_GUEST_RIP, (ULONG64)AsmVMXRestoreState);
}

/// <summary>
/// Sets up all the VMCS control data.
/// </summary>
VOID SetupVmcsControlData() 
{
    DbgPrint("[hypoo] Setting up VMCS controls");

    IA32_VMX_PINBASED_CTLS_REGISTER PinbasedControls = { 0 };
    IA32_VMX_PROCBASED_CTLS_REGISTER ProcbasedControls = { 0 };
    IA32_VMX_PROCBASED_CTLS2_REGISTER SecondaryControls = { 0 };
    IA32_VMX_ENTRY_CTLS_REGISTER EntryControls = { 0 };
    IA32_VMX_EXIT_CTLS_REGISTER ExitControls = { 0 };

    // ------------ VM Entry Controls ------------

    EntryControls.Ia32EModeGuest = TRUE;

    SetEntryControls(&EntryControls);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, EntryControls.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    //__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);

    // ------------ VM Exit Controls ------------

    ExitControls.HostAddressSpaceSize = TRUE;

    SetExitControls(&ExitControls);

    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, ExitControls.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

    // ------------ Procbased Controls ------------

    ProcbasedControls.ActivateSecondaryControls = TRUE;
    ProcbasedControls.UseMsrBitmaps = TRUE;

    SetProcbasedControls(&ProcbasedControls);

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ProcbasedControls.AsUInt);

    // ------------ Secondary Procbased Controls ------------

    //SecondaryControls.EnableEpt = TRUE; // testing

    SecondaryControls.EnableRdtscp = TRUE;
    SecondaryControls.EnableInvpcid = TRUE;
    SecondaryControls.EnableXsaves = TRUE;

    SetSecondaryControls(&SecondaryControls);

    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, SecondaryControls.AsUInt);

    // ------------ Secondary Procbased Controls ------------

    SetPinbasedControls(&PinbasedControls);

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, PinbasedControls.AsUInt);

    // ------------ Other Controls ------------

    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);

    /*
    * An execution of MOV to CR3 in VMX non-root operation does not cause a VM exit if its source operand matches one of these values
    */
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_0, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_1, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_2, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_3, 0);

    // testing
    __vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, 0);
    __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, 0);
    // end testing

    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, g_GuestState->MsrBitmapPhysicalAddress);

    //__vmx_vmwrite(VMCS_CTRL_EPT_POINTER, g_EptState->EptPointer.AsUInt); // testing
}

/// <summary>
/// 
/// </summary>
/// <param name="EntryControls"></param>
VOID SetEntryControls(IA32_VMX_ENTRY_CTLS_REGISTER* EntryControls) 
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = BasicControls.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

    AdjustControl(CapabilityMSR, &EntryControls->AsUInt);
}

/// <summary>
/// 
/// </summary>
/// <param name="ExitControls"></param>
VOID SetExitControls(IA32_VMX_EXIT_CTLS_REGISTER* ExitControls) 
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = BasicControls.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS;

    AdjustControl(CapabilityMSR, &ExitControls->AsUInt);
}

/// <summary>
/// 
/// </summary>
/// <param name="PinbasedControls"></param>
VOID SetPinbasedControls(IA32_VMX_PINBASED_CTLS_REGISTER* PinbasedControls) 
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = BasicControls.VmxControls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS;

    AdjustControl(CapabilityMSR, &PinbasedControls->AsUInt);
}

/// <summary>
/// 
/// </summary>
/// <param name="ProcbasedControls"></param>
VOID SetProcbasedControls(IA32_VMX_PROCBASED_CTLS_REGISTER* ProcbasedControls) 
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = BasicControls.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS;

    AdjustControl(CapabilityMSR, &ProcbasedControls->AsUInt);
}

/// <summary>
/// 
/// </summary>
/// <param name="SecondaryControls"></param>
VOID SetSecondaryControls(IA32_VMX_PROCBASED_CTLS2_REGISTER* SecondaryControls) 
{
    IA32_VMX_BASIC_REGISTER BasicControls = GetBasicControls();

    UINT32 CapabilityMSR = IA32_VMX_PROCBASED_CTLS2;

    AdjustControl(CapabilityMSR, &SecondaryControls->AsUInt);
}

/// <summary>
/// 
/// </summary>
/// <param name="CapabilityMSR"></param>
/// <param name="Value"></param>
VOID AdjustControl(UINT32 CapabilityMSR, UINT32* Value) 
{
    IA32_VMX_TRUE_CTLS_REGISTER Capabilities = { 0 };

    Capabilities.AsUInt = __readmsr(CapabilityMSR);

    *Value |= Capabilities.Allowed0Settings;
    *Value &= Capabilities.Allowed1Settings;
}

IA32_VMX_BASIC_REGISTER GetBasicControls()
{
    IA32_VMX_BASIC_REGISTER BasicControls = { 0 };

    BasicControls.AsUInt = __readmsr(IA32_VMX_BASIC);

    return BasicControls;
}

BOOLEAN SetupVmcs(VIRTUAL_MACHINE_STATE* GuestState, PVOID GuestStack) 
{
    SEGMENT_DESCRIPTOR_REGISTER_64*  Gdtr = { 0 };
    SEGMENT_DESCRIPTOR_REGISTER_64*  Idtr = { 0 };

    SetupVmcsControlData();

    SetupVmcsGuestData(&Gdtr, &Idtr, GuestStack);
    SetupVmcsHostData(&Gdtr, &Idtr);
    
    DbgPrint("[hypoo] VMCS was setup successfully (i think lul)");

    //DebugVmcs(&Gdtr, &Idtr);

    return TRUE;
}

// https://revers.engineering/day-4-vmcs-segmentation-ops/
UINT32 ReadSegmentAccessRights(UINT16 SegmentSelector) 
{
    SEGMENT_SELECTOR Selector = { 0 };
    VMX_SEGMENT_ACCESS_RIGHTS VmxAccessRights = { 0 };

    Selector.AsUInt = SegmentSelector;

    //
    // Check for null selector use, if found set access right to unusable
    // and return. Otherwise, get access rights, modify format, return the
    // segment access rights.
    //
    if (Selector.Table == 0 && Selector.Index == 0) 
    {
        VmxAccessRights.AsUInt = 0;
        VmxAccessRights.Unusable = TRUE;
        return VmxAccessRights.AsUInt;
    }

    //
    // Use our custom intrinsic to store our access rights, and
    // remember that the first byte of the access rights returned
    // are not used in VMX access right format.
    //
    
    VmxAccessRights.AsUInt = (__load_ar(Selector) >> 8);
    VmxAccessRights.Unusable = 0;
    VmxAccessRights.Reserved1 = 0;
    VmxAccessRights.Reserved2 = 0;

    return VmxAccessRights.AsUInt;
}

UINT64 GetSegmentBase(UINT64 GdtBase, UINT16 SegmentSelector)
{
    UINT64 SegmentBase = 0;
    SEGMENT_SELECTOR Selector = { 0 };
    SEGMENT_DESCRIPTOR_32* Descriptor = { 0 };
    SEGMENT_DESCRIPTOR_32* DescsriptorTable = { 0 };

    Selector.AsUInt = SegmentSelector;

    if (Selector.Table == 0 && Selector.Index == 0)
    {
        return SegmentBase; // already 0;
    }

    DescsriptorTable = (SEGMENT_DESCRIPTOR_32*)GdtBase;
    Descriptor = &DescsriptorTable[Selector.Index];

    UINT32 BaseHigh = Descriptor->BaseAddressHigh << 24;
    UINT32 BaseMid = Descriptor->BaseAddressMiddle << 16;
    UINT32 BaseLow = Descriptor->BaseAddressLow;

    SegmentBase = (BaseHigh | BaseMid | BaseLow) & 0xFFFFFFFF;
    
    //
    // As mentioned in the discussion in the article, some system descriptors are expanded
    // to 16 bytes on Intel 64 architecture. We only need to pay attention to the TSS descriptors
    // and we'll use our expanded descriptor structure to adjust the segment base.
    //

    if ((Descriptor->System == 0) &&
        ((Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE) ||
            (Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY)))
    {
        SEGMENT_DESCRIPTOR_64* ExpandedDescriptor;
        ExpandedDescriptor = (SEGMENT_DESCRIPTOR_64*)Descriptor;

        SegmentBase |= ((UINT64)ExpandedDescriptor->BaseAddressUpper << 32);
    }

    return SegmentBase;
}

ULONG AdjustControls(ULONG CTL_CODE, ULONG Msr) 
{
    MSR MsrValue = { 0 };

    MsrValue.Content = __readmsr(Msr);
    CTL_CODE &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
    CTL_CODE |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
    return CTL_CODE;
}

/// <summary>
/// Omega debug print lul
/// </summary>
/// <param name="Gdtr"></param>
/// <param name="Idtr"></param>
/// <returns></returns>
VOID DebugVmcs(SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr, SEGMENT_DESCRIPTOR_REGISTER_64* Idtr)
{
    DbgPrint("==================DEBUG==================");

    DbgPrint("==================CAPABILITIES==================\n");

    DbgPrint("[0x%016X] = IA32_VMX_BASIC", __readmsr(IA32_VMX_BASIC));

    DbgPrint("[0x%016X] = IA32_VMX_PINBASED_CTLS", __readmsr(IA32_VMX_PINBASED_CTLS));

    DbgPrint("[0x%016X] = IA32_VMX_PROCBASED_CTLS", __readmsr(IA32_VMX_PROCBASED_CTLS));

    DbgPrint("[0x%016X] = IA32_VMX_PROCBASED_CTLS2", __readmsr(IA32_VMX_PROCBASED_CTLS2));

    DbgPrint("[0x%016X] = IA32_VMX_EXIT_CTLS", __readmsr(IA32_VMX_EXIT_CTLS));

    DbgPrint("[0x%016X] = IA32_VMX_ENTRY_CTLS", __readmsr(IA32_VMX_ENTRY_CTLS));

    DbgPrint("[0x%016X] = IA32_VMX_MISC", __readmsr(IA32_VMX_MISC));

    DbgPrint("[0x%016X] = IA32_VMX_EPT_VPID_CAP", __readmsr(IA32_VMX_EPT_VPID_CAP));

    DbgPrint("[0x%016X] = IA32_VMX_VMFUNC", __readmsr(IA32_VMX_VMFUNC));

    DbgPrint("[0x%016X] = IA32_VMX_CR0_FIXED0", __readmsr(IA32_VMX_CR0_FIXED0));

    DbgPrint("[0x%016X] = IA32_VMX_CR0_FIXED1", __readmsr(IA32_VMX_CR0_FIXED1));

    DbgPrint("[0x%016X] = IA32_VMX_CR4_FIXED0", __readmsr(IA32_VMX_CR4_FIXED0));

    DbgPrint("[0x%016X] = IA32_VMX_CR4_FIXED1", __readmsr(IA32_VMX_CR4_FIXED1));

    DbgPrint("[0x%016X] = IA32_VMX_VMCS_ENUM", __readmsr(IA32_VMX_VMCS_ENUM));

    DbgPrint("[0x%016X] = IA32_VMX_TRUE_PINBASED_CTLS", __readmsr(IA32_VMX_TRUE_PINBASED_CTLS));

    DbgPrint("[0x%016X] = IA32_VMX_TRUE_PROCBASED_CTLS", __readmsr(IA32_VMX_TRUE_PROCBASED_CTLS));

    DbgPrint("[0x%016X] = IA32_VMX_TRUE_ENTRY_CTLS", __readmsr(IA32_VMX_TRUE_ENTRY_CTLS));

    DbgPrint("[0x%016X] = IA32_VMX_TRUE_EXIT_CTLS", __readmsr(IA32_VMX_TRUE_EXIT_CTLS));


    DbgPrint("==================HOST STATE==================\n");

    UINT64 cr0 = __readcr0();
    DbgPrint("host_state.cr0: [0x%02X]", cr0);

    UINT64 cr3 = __readcr3();
    DbgPrint("host_state.cr3: [0x%02X]", cr3);

    UINT64 cr4 = __readcr4();
    DbgPrint("host_state.cr4: [0x%02X]", cr4);

    UINT64 efer_msr = __readmsr(IA32_EFER);
    DbgPrint("host_state.efer_msr: [0x%02X]", efer_msr);

    UINT64 fs_base = __readmsr(IA32_FS_BASE);
    DbgPrint("host_state.fs_base: [0x%02X]", fs_base);

    // gdtr_base
    DbgPrint("host_state.gdtr_base: [0x%02X]", Gdtr->BaseAddress);

    UINT64 gs_base = __readmsr(IA32_GS_BASE);
    DbgPrint("host_state.gs_base: [0x%02X]", gs_base);

    // idtr_base
    DbgPrint("host_state.idtr_base: [0x%02X]", Idtr->BaseAddress);

    UINT64 pat_msr = __readmsr(IA32_PAT);
    DbgPrint("host_state.pat_msr: [0x%02X]", pat_msr);

    DbgPrint("host_state.rip: [0x%02X]", (ULONG64)AsmVmexitHandler);

    DbgPrint("host_state.rsp: [0x%02X]", ((ULONG64)g_GuestState->VmmStack + VMM_STACK_SIZE - 1));

    DbgPrint("host_state.selector_es: [0x%02X]", GetEs());
    DbgPrint("host_state.selector_cs: [0x%02X]", GetCs());
    DbgPrint("host_state.selector_ss: [0x%02X]", GetSs());
    DbgPrint("host_state.selector_ds: [0x%02X]", GetDs());
    DbgPrint("host_state.selector_fs: [0x%02X]", GetFs());
    DbgPrint("host_state.selector_gs: [0x%02X]", GetGs());

    UINT64 sysenter_cs_msr = __readmsr(IA32_SYSENTER_CS);
    DbgPrint("host_state.sysenter_cs_msr: [0x%02X]", sysenter_cs_msr);

    UINT64 sysenter_eip_msr = __readmsr(IA32_SYSENTER_EIP);
    DbgPrint("host_state.sysenter_eip_msr: [0x%02X]", sysenter_eip_msr);

    UINT64 sysenter_esp_msr = __readmsr(IA32_SYSENTER_ESP);

    DbgPrint("host_state.sysenter_esp_msr: [0x%02X]", sysenter_esp_msr);

    DbgPrint("host_state.tr_base: [0x%02X]", GetSegmentBase(Gdtr->BaseAddress, GetTr()));

    DbgPrint("vmxon_ptr: [0x%02X]", g_GuestState->VmxonRegionVirtualAddress);

    DbgPrint("==================CONTROLS==================");

    UINT32 Control32Bit = 0;

    __vmx_vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS", Control32Bit);

    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS", Control32Bit);

    __vmx_vmread(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS", Control32Bit);

    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_EXCEPTION_BITMAP", Control32Bit);

    __vmx_vmread(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK", Control32Bit);

    __vmx_vmread(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR0_GUEST_HOST_MASK, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR0_GUEST_HOST_MASK", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR4_GUEST_HOST_MASK, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR4_GUEST_HOST_MASK", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR0_READ_SHADOW", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR4_READ_SHADOW, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR4_READ_SHADOW", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR3_TARGET_COUNT, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR3_TARGET_COUNT", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR3_TARGET_VALUE_0, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR3_TARGET_VALUE_0", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR3_TARGET_VALUE_1, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR3_TARGET_VALUE_1", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR3_TARGET_VALUE_2, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR3_TARGET_VALUE_2", Control32Bit);

    __vmx_vmread(VMCS_CTRL_CR3_TARGET_VALUE_3, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_CTRL_CR3_TARGET_VALUE_3", Control32Bit);

    __vmx_vmread(VMCS_GUEST_RFLAGS, &Control32Bit);
    DbgPrint("[0x%08X] = VMCS_GUEST_RFLAGS", Control32Bit);

    DbgPrint("============================================\n");
}
