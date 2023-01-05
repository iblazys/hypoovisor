#include "vmcs.h"

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

    return 0; // use this pointer for something?
}

/// <summary>
/// Clears the state of the current vcpu vmcs region
/// </summary>
BOOLEAN ClearVmcsState(VIRTUAL_MACHINE_STATE* GuestState)
{
    // Clear the state of the VMCS to inactive
    int status = __vmx_vmclear(&GuestState->VmcsRegion);

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
    int status = __vmx_vmptrld(&GuestState->VmcsRegion);
    if (status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", status);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN SetupVmcs(VIRTUAL_MACHINE_STATE* GuestState, EPT_POINTER* EPTP) 
{
    SEGMENT_DESCRIPTOR_REGISTER_64  Gdtr = { 0 };
    SEGMENT_DESCRIPTOR_REGISTER_64  Idtr = { 0 };

    DbgPrint("GetEs RETURNED: %02X", GetEs());
    DbgPrint("GetCs RETURNED: %02X", GetCs());
    DbgPrint("GetSs RETURNED: %02X", GetSs());
    DbgPrint("GetDs RETURNED: %02X", GetDs());
    DbgPrint("GetFs RETURNED: %02X", GetFs());
    DbgPrint("GetGs RETURNED: %02X", GetGs());
    DbgPrint("GetLdtr RETURNED: %02X", GetLdtr()); // LDTR returning 0
    DbgPrint("GetTr RETURNED: %02X", GetTr());

    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, GetEs() & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, GetCs() & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, GetSs() & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, GetDs() & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, GetFs() & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, GetGs() & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, GetTr() & 0xFFF8);

    // Setting the link pointer to the required value for 4KB VMCS
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);

    // Unused in this hypervisor for now
    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL) & 0xFFFFFFFF);
    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL + 1, __readmsr(IA32_DEBUGCTL) >> 32); // VMCS_GUEST_DEBUGCTL_HIGH, 0x00002803, not in ia32.h

    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);
    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET + 1, 0); // VMCS_CTRL_TSC_OFFSET_HIGH, 0x00002010, not in ia32.h

    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    //
    // Segmentation
    //

    // Selectors
    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, GetCs());
    __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, GetSs());
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, GetDs());
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, GetEs());
    __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, GetFs());
    __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, GetGs());
    __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, GetLdtr());
    __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, GetTr());

    // Limits
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, __segmentlimit(GetCs()));
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, __segmentlimit(GetSs()));
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, __segmentlimit(GetDs()));
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, __segmentlimit(GetEs()));
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, __segmentlimit(GetFs()));
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, __segmentlimit(GetGs()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(GetLdtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, __segmentlimit(GetTr()));

    _sgdt(&Gdtr); // not in intrin.h ??
    __sidt(&Idtr);

    DbgPrint("Gdtr->Limit: %02X", Gdtr.Limit);
    DbgPrint("Gdtr->BaseAddress: %02X", Gdtr.BaseAddress);
    DbgPrint("Idtr->Limit: %02X", Idtr.Limit);
    DbgPrint("Idtr->BaseAddress: %02X", Idtr.BaseAddress);

    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, Gdtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, Idtr.Limit);
       
    // Base
    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, Gdtr.BaseAddress);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, Idtr.BaseAddress);

    // Access Rights
    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetCs()));
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetSs()));
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetDs()));
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, ReadSegmentAccessRights(GetEs()));
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetFs()));
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, ReadSegmentAccessRights(GetGs()));
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, ReadSegmentAccessRights(GetLdtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, ReadSegmentAccessRights(GetTr()));
     
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, GetSegmentBase(Gdtr.BaseAddress, GetLdtr()));
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, GetSegmentBase(Gdtr.BaseAddress, GetTr()));

    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);   //Active state 

    // read the msr
    //IA32_VMX_ENTRY_CTLS_REGISTER registers;
    //registers.AsUInt = __readmsr(IA32_VMX_ENTRY_CTLS);

    //registers.Ia32EModeGuest;

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, IA32_VMX_PROCBASED_CTLS2));

    
    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, AdjustControls(0, IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_0, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_1, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_2, 0);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_3, 0);

    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, GetRflags());

    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_HOST_TR_BASE, GetSegmentBase(Gdtr.BaseAddress, GetTr()));

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, Gdtr.BaseAddress);
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, Idtr.BaseAddress);

    __vmx_vmwrite(VMCS_GUEST_RSP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest sp
    __vmx_vmwrite(VMCS_GUEST_RIP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest ip

    __vmx_vmwrite(VMCS_HOST_RSP, ((ULONG64)GuestState->VmmStack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(VMCS_HOST_RIP, (ULONG64)AsmVmexitHandler);

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

/*
// these functions are from 2015 lol... hard to match these old names up with ia32.h
VOID FillGuestSelectorData(PVOID GdtBase, ULONG Segreg, USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = { 0 };
    ULONG            AccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR + Segreg * 2, Selector);
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS + Segreg * 2, AccessRights);
    __vmx_vmwrite(VMCS_GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}
// these functions are from 2015 lol...... hard to match these old names up with ia32.h
//
// SEGMENT_SELECTOR_64 looks like "SEGMENT_SELECTOR" ? what about the attributes though?
// VMX_SEGMENT_ACCESS_RIGHTS looks like "SEGMENT_ATTRIBUTES" ?
//
BOOLEAN GetSegmentDescriptor(SEGMENT_SELECTOR* SegmentSelector, USHORT Selector, PUCHAR GdtBase)
{
    SEGMENT_DESCRIPTOR_64* SegDesc;

    if (!SegmentSelector)
        return FALSE;

    if (Selector & 0x4)
    {
        return FALSE;
    }

    SegDesc = (SEGMENT_DESCRIPTOR_64*)((PUCHAR)GdtBase + (Selector & ~0x7));

    SegmentSelector-> = Selector;
    SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10))
    { // LA_ACCESSED
        ULONG64 Tmp;
        // this is a TSS or callgate etc, save the base high part
        Tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G)
    {
        // 4096-bit granularity is enabled for this segment, scale the limit
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}
*/