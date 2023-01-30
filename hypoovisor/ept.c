#include "hypoovisor.h"
#include "ept.h"
#include "vmstate.h"
#include "shared.h"
#include "memory.h"
#include "vmcall.h"

UINT64 InitializeEptPointer()
{
	PAGED_CODE();

    // Allocate EPT_POINTER
    EPT_POINTER* EPTPointer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EPTPointer)
    {
        return NULL;
    }
    RtlZeroMemory(EPTPointer, PAGE_SIZE);

    //  Allocate EPT PML4
    EPT_PML4E* EptPml4 = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EptPml4)
    {
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPml4, PAGE_SIZE);

    //  Allocate EPT Page-Directory-Pointer-Table
    EPT_PDPTE* EptPdpt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EptPdpt)
    {
        ExFreePoolWithTag(EptPml4, POOLTAG);
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPdpt, PAGE_SIZE);

    //  Allocate EPT Page-Directory
    EPT_PDE* EptPd = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EptPd)
    {
        ExFreePoolWithTag(EptPdpt, POOLTAG);
        ExFreePoolWithTag(EptPml4, POOLTAG);
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPd, PAGE_SIZE);

    //  Allocate EPT Page-Table
    EPT_PTE* EptPt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EptPt)
    {
        ExFreePoolWithTag(EptPd, POOLTAG);
        ExFreePoolWithTag(EptPdpt, POOLTAG);
        ExFreePoolWithTag(EptPml4, POOLTAG);
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPt, PAGE_SIZE);

    // Setup PT by allocating two pages Continuously
    // We allocate two pages because we need 1 page for our RIP to start and 1 page for RSP 1 + 1 = 2
    const int PagesToAllocate = 100;
    UINT64    GuestMemory = ExAllocatePoolWithTag(NonPagedPool, PagesToAllocate * PAGE_SIZE, POOLTAG);
    RtlZeroMemory(GuestMemory, PagesToAllocate * PAGE_SIZE);

    g_VirtualGuestMemoryAddress = GuestMemory;

    for (size_t i = 0; i < PagesToAllocate; i++)
    {
        EptPt[i].Accessed = 0;
        EptPt[i].Dirty = 0;
        EptPt[i].MemoryType = 6; // 0 = Uncached,  6 = Writeback
        EptPt[i].ExecuteAccess = 1;
        EptPt[i].UserModeExecute = 0;
        EptPt[i].IgnorePat = 0;
        EptPt[i].PageFrameNumber = (VirtualToPhysicalAddress(GuestMemory + (i * PAGE_SIZE)) / PAGE_SIZE);
        EptPt[i].ReadAccess = 1;
        EptPt[i].SuppressVe = 0;
        EptPt[i].WriteAccess = 1;

        //EptPt[i].SupervisorShadowStack
        //EptPt[i].VerifyGuestPaging;
        //EptPt[i].SubPageWritePermissions
    }

    //
    // Setting up PDE
    //
    EptPd->Accessed = 0;
    EptPd->ExecuteAccess = 1;
    EptPd->UserModeExecute = 0;
    EptPd->PageFrameNumber = (VirtualToPhysicalAddress(EptPt) / PAGE_SIZE);
    EptPd->ReadAccess = 1;
    EptPd->Reserved1 = 0;
    EptPd->Reserved2 = 0;
    EptPd->Reserved3 = 0;
    EptPd->Reserved4 = 0;
    EptPd->WriteAccess = 1;

    //
    // Setting up PDPTE
    //
    EptPdpt->Accessed = 0;
    EptPdpt->ExecuteAccess = 1;
    EptPdpt->UserModeExecute = 0;
    EptPdpt->PageFrameNumber = (VirtualToPhysicalAddress(EptPd) / PAGE_SIZE);
    EptPdpt->ReadAccess = 1;
    EptPdpt->Reserved1 = 0;
    EptPdpt->Reserved2 = 0;
    EptPdpt->Reserved3 = 0;
    EptPdpt->Reserved4 = 0;
    EptPdpt->WriteAccess = 1;

    //
    // Setting up PML4E
    //
    EptPml4->Accessed = 0;
    EptPml4->ExecuteAccess = 1;
    EptPml4->UserModeExecute = 0;
    EptPml4->PageFrameNumber = (VirtualToPhysicalAddress(EptPdpt) / PAGE_SIZE);
    EptPml4->ReadAccess = 1;
    EptPml4->Reserved1 = 0;
    EptPml4->Reserved2 = 0;
    EptPml4->Reserved3 = 0;
    EptPml4->Reserved4 = 0;
    EptPml4->WriteAccess = 1;

    //
    // Setting up EPTP
    //
    EPTPointer->EnableAccessAndDirtyFlags = 1;
    EPTPointer->MemoryType = 6; // 6 = Write-back (WB)
    EPTPointer->PageWalkLength = 3; // 4, (tables walked) - 1 = 3
    EPTPointer->PageFrameNumber = (VirtualToPhysicalAddress(EptPml4) / PAGE_SIZE);
    EPTPointer->Reserved1 = 0;
    EPTPointer->Reserved2 = 0;

    // eventually
    //EPTPointer->EnableSupervisorShadowStackPages; 
    //EPTPointer->EnableAccessAndDirtyFlags;

    DbgPrint("[*] Extended Page Table Pointer allocated at %llx", EPTPointer);
    return EPTPointer;
}

BOOLEAN EptCheckFeatures()
{
    IA32_VMX_EPT_VPID_CAP_REGISTER VpidRegister = { 0 };
    IA32_MTRR_DEF_TYPE_REGISTER MTRRDefType = { 0 };

    VpidRegister.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);
    MTRRDefType.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (!VpidRegister.PageWalkLength4 || !VpidRegister.MemoryTypeWriteBack || !VpidRegister.Pde2MbPages)
    {
        return FALSE;
    }

    if (!VpidRegister.AdvancedVmexitEptViolationsInformation)
    {
        LogWarning("The processor doesn't report advanced VM-exit information for EPT violations");
    }

    if (!MTRRDefType.MtrrEnable)
    {
        LogError("Mtrr Dynamic Ranges not supported");
        return FALSE;
    }

    LogInfo(" *** All EPT features are present *** ");

    return TRUE;
}

BOOLEAN EptLogicalProcessorInitialize()
{
    PVMM_EPT_PAGE_TABLE PageTable;
    EPT_POINTER EPTP = { 0 };

    /* Allocate the identity mapped page table*/
    PageTable = EptAllocateAndCreateIdentityPageTable();
    if (!PageTable)
    {
        LogError("Unable to allocate memory for EPT");
        return FALSE;
    }

    // Virtual address to the page table to keep track of it for later freeing 
    g_EptState->EptPageTable = PageTable;

    EPTP.AsUInt = 0;

    // For performance, we let the processor know it can cache the EPT.
    EPTP.MemoryType = MEMORY_TYPE_WRITE_BACK;

    // We are not utilizing the 'access' and 'dirty' flag features. 
    EPTP.EnableAccessAndDirtyFlags = FALSE;

    /*
      Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
      see Section 28.2.2
     */
    EPTP.PageWalkLength = 3;

    // The physical page number of the page table we will be using 
    EPTP.PageFrameNumber = (SIZE_T)VirtualToPhysicalAddress(&PageTable->PML4) / PAGE_SIZE;

    // We will write the EPTP to the VMCS later 
    g_EptState->EptPointer = EPTP;

    //
    // TESTERINO
    //
    
    //LogInfo("Testing ExAllocatePoolWithTag in VMX non root");
    EptPageHook(ExAllocatePoolWithTag, FALSE);

    return TRUE;
}

BOOLEAN EptBuildMtrrMap()
{
    
    IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
    IA32_MTRR_PHYSBASE_REGISTER CurrentPhysBase;
    IA32_MTRR_PHYSMASK_REGISTER CurrentPhysMask;
    PMTRR_RANGE_DESCRIPTOR Descriptor;
    ULONG CurrentRegister;
    ULONG NumberOfBitsInMask;


    MTRRCap.AsUInt = __readmsr(IA32_MTRR_CAPABILITIES);

    for (CurrentRegister = 0; CurrentRegister < MTRRCap.VariableRangeCount; CurrentRegister++)
    {
        // For each dynamic register pair
        CurrentPhysBase.AsUInt = __readmsr(IA32_MTRR_PHYSBASE0 + (CurrentRegister * 2));
        CurrentPhysMask.AsUInt = __readmsr(IA32_MTRR_PHYSMASK0 + (CurrentRegister * 2));

        // Is the range enabled?
        if (CurrentPhysMask.Valid)
        {
            // We only need to read these once because the ISA dictates that MTRRs are to be synchronized between all processors
            // during BIOS initialization.
            Descriptor = &g_EptState->MemoryRanges[g_EptState->NumberOfEnabledMemoryRanges++];

            // Calculate the base address in bytes
            Descriptor->PhysicalBaseAddress = CurrentPhysBase.PageFrameNumber * PAGE_SIZE;

            // Calculate the total size of the range
            // The lowest bit of the mask that is set to 1 specifies the size of the range
            _BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.PageFrameNumber * PAGE_SIZE);

            // Size of the range in bytes + Base Address
            Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

            // Memory Type (cacheability attributes)
            Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Type;

            if (Descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
            {
                // This is already our default, so no need to store this range.
                //Simply 'free' the range we just wrote.
                g_EptState->NumberOfEnabledMemoryRanges--;
            }
            LogInfo("MTRR Range: Base=0x%llx End=0x%llx Type=0x%x", Descriptor->PhysicalBaseAddress, Descriptor->PhysicalEndAddress, Descriptor->MemoryType);
        }
    }

    LogInfo("Total MTRR Ranges Committed: %d", g_EptState->NumberOfEnabledMemoryRanges);
    
    return TRUE;
}

PVMM_EPT_PAGE_TABLE EptAllocateAndCreateIdentityPageTable()
{
    PVMM_EPT_PAGE_TABLE PageTable = { 0 };
    EPT_PML3_POINTER RWXTemplate = { 0 };
    EPT_PML2_ENTRY PML2EntryTemplate = { 0 };
    SIZE_T EntryGroupIndex;
    SIZE_T EntryIndex;

    // Allocate all paging structures as 4KB aligned pages 
    PHYSICAL_ADDRESS MaxSize = { 0 };

    PVOID Output = NULL; // unused

    // Allocate address anywhere in the OS's memory space
    MaxSize.QuadPart = MAXULONG64;

    PageTable = MmAllocateContiguousMemory((sizeof(VMM_EPT_PAGE_TABLE) / PAGE_SIZE) * PAGE_SIZE, MaxSize);

    if (PageTable == NULL)
    {
        //LogError("Failed to allocate memory for PageTable");
        return NULL;
    }

    // Zero out all entries to ensure all unused entries are marked Not Present 
    RtlZeroMemory(PageTable, sizeof(VMM_EPT_PAGE_TABLE));

    // Initialize the dynamic split list which holds all dynamic page splits 
    InitializeListHead(&PageTable->DynamicSplitList);

    // Mark the first 512GB PML4 entry as present, which allows us to manage up to 512GB of discrete paging structures. 
    PageTable->PML4[0].PageFrameNumber = (SIZE_T)VirtualToPhysicalAddress(&PageTable->PML3[0]) / PAGE_SIZE;
    PageTable->PML4[0].ReadAccess = 1;
    PageTable->PML4[0].WriteAccess = 1;
    PageTable->PML4[0].ExecuteAccess = 1;

    /* Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry */

    // Ensure stack memory is cleared
    RWXTemplate.AsUInt = 0;

    // Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries 
    // Using the same method as SimpleVisor for copying each entry using intrinsics. 
    RWXTemplate.ReadAccess = 1;
    RWXTemplate.WriteAccess = 1;
    RWXTemplate.ExecuteAccess = 1;

    // Copy the template into each of the 512 PML3 entry slots 
    __stosq((SIZE_T*)&PageTable->PML3[0], RWXTemplate.AsUInt, VMM_EPT_PML3E_COUNT);

    // For each of the 512 PML3 entries 
    for (EntryIndex = 0; EntryIndex < VMM_EPT_PML3E_COUNT; EntryIndex++)
    {
        // Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
        // NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
        PageTable->PML3[EntryIndex].PageFrameNumber = (SIZE_T)VirtualToPhysicalAddress(&PageTable->PML2[EntryIndex][0]) / PAGE_SIZE;
    }

    PML2EntryTemplate.AsUInt = 0;

    // All PML2 entries will be RWX and 'present' 
    PML2EntryTemplate.WriteAccess = 1;
    PML2EntryTemplate.ReadAccess = 1;
    PML2EntryTemplate.ExecuteAccess = 1;

    // We are using 2MB large pages, so we must mark this 1 here. 
    PML2EntryTemplate.LargePage = 1;

    /* For each collection of 512 PML2 entries (512 collections * 512 entries per collection), mark it RWX using the same template above.
       This marks the entries as "Present" regardless of if the actual system has memory at this region or not. We will cause a fault in our
       EPT handler if the guest access a page outside a usable range, despite the EPT frame being present here.
     */
    __stosq((SIZE_T*)&PageTable->PML2[0], PML2EntryTemplate.AsUInt, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

    // For each of the 512 collections of 512 2MB PML2 entries 
    for (EntryGroupIndex = 0; EntryGroupIndex < VMM_EPT_PML3E_COUNT; EntryGroupIndex++)
    {
        // For each 2MB PML2 entry in the collection 
        for (EntryIndex = 0; EntryIndex < VMM_EPT_PML2E_COUNT; EntryIndex++)
        {
            // Setup the memory type and frame number of the PML2 entry. 
            EptSetupPML2Entry(&PageTable->PML2[EntryGroupIndex][EntryIndex], (EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex);
        }
    }

    return PageTable;
}

PEPT_PML1_ENTRY EptGetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    SIZE_T Directory, DirectoryPointer, PML4Entry;
    PEPT_PML2_ENTRY PML2;
    PEPT_PML1_ENTRY PML1;
    PEPT_PML2_POINTER PML2Pointer;

    Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
    DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
    PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

    // Addresses above 512GB are invalid because it is > physical address bus width 
    if (PML4Entry > 0)
    {
        return NULL;
    }

    PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];

    // Check to ensure the page is split 
    if (PML2->LargePage)
    {
        return NULL;
    }

    // Conversion to get the right PageFrameNumber.
    // These pointers occupy the same place in the table and are directly convertable.
    PML2Pointer = (PEPT_PML2_POINTER)PML2;

    // If it is, translate to the PML1 pointer 
    PML1 = (PEPT_PML1_ENTRY)PhysicalToVirtualAddress((PVOID)(PML2Pointer->PageFrameNumber * PAGE_SIZE));

    if (!PML1)
    {
        return NULL;
    }

    // Index into PML1 for that address 
    PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

    return PML1;
}

VOID EptSetupPML2Entry(PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber)
{
    SIZE_T AddressOfPage;
    SIZE_T CurrentMtrrRange;
    SIZE_T TargetMemoryType;

    /*
      Each of the 512 collections of 512 PML2 entries is setup here.
      This will, in total, identity map every physical address from 0x0 to physical address 0x8000000000 (512GB of memory)
      ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is the actual physical address we're mapping
     */
    NewEntry->PageFrameNumber = PageFrameNumber;

    // Size of 2MB page * PageFrameNumber == AddressOfPage (physical memory). 
    AddressOfPage = PageFrameNumber * SIZE_2_MB;

    /* To be safe, we will map the first page as UC as to not bring up any kind of undefined behavior from the
      fixed MTRR section which we are not formally recognizing (typically there is MMIO memory in the first MB).
      I suggest reading up on the fixed MTRR section of the manual to see why the first entry is likely going to need to be UC.
     */
    if (PageFrameNumber == 0)
    {
        NewEntry->MemoryType = MEMORY_TYPE_UNCACHEABLE;
        return;
    }

    // Default memory type is always WB for performance. 
    TargetMemoryType = MEMORY_TYPE_WRITE_BACK;

    // For each MTRR range 
    for (CurrentMtrrRange = 0; CurrentMtrrRange < g_EptState->NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
    {
        // If this page's address is below or equal to the max physical address of the range 
        if (AddressOfPage <= g_EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress)
        {
            // And this page's last address is above or equal to the base physical address of the range 
            if ((AddressOfPage + SIZE_2_MB - 1) >= g_EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress)
            {
                /* If we're here, this page fell within one of the ranges specified by the variable MTRRs
                   Therefore, we must mark this page as the same cache type exposed by the MTRR
                 */
                TargetMemoryType = g_EptState->MemoryRanges[CurrentMtrrRange].MemoryType;
                // LogInfo("0x%X> Range=%llX -> %llX | Begin=%llX End=%llX", PageFrameNumber, AddressOfPage, AddressOfPage + SIZE_2_MB - 1, EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress, EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress);

                // 11.11.4.1 MTRR Precedences 
                if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
                {
                    // If this is going to be marked uncacheable, then we stop the search as UC always takes precedent. 
                    break;
                }
            }
        }
    }

    // Finally, commit the memory type to the entry. 
    NewEntry->MemoryType = TargetMemoryType;
}

PEPT_PML2_ENTRY EptGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    SIZE_T Directory, DirectoryPointer, PML4Entry;
    PEPT_PML2_ENTRY PML2;

    Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
    DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
    PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

    // Addresses above 512GB are invalid because it is > physical address bus width 
    if (PML4Entry > 0)
    {
        return NULL;
    }

    PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];
    return PML2;
}

BOOLEAN EptSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, PVOID PreAllocatedBuffer, SIZE_T PhysicalAddress, ULONG CoreIndex)
{
    PVMM_EPT_DYNAMIC_SPLIT NewSplit;
    EPT_PML1_ENTRY EntryTemplate;
    SIZE_T EntryIndex;
    PEPT_PML2_ENTRY TargetEntry;
    EPT_PML2_POINTER NewPointer;

    // Find the PML2 entry that's currently used
    TargetEntry = EptGetPml2Entry(EptPageTable, PhysicalAddress);
    if (!TargetEntry)
    {
        LogError("An invalid physical address passed");
        return FALSE;
    }

    // If this large page is not marked a large page, that means it's a pointer already.
    // That page is therefore already split.
    if (!TargetEntry->LargePage)
    {
        return TRUE;
    }

    // Free previous buffer 
    g_GuestState[CoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer = NULL;

    // Allocate the PML1 entries 
    NewSplit = (PVMM_EPT_DYNAMIC_SPLIT)PreAllocatedBuffer;
    if (!NewSplit)
    {
        LogError("Failed to allocate dynamic split memory");
        return FALSE;
    }
    RtlZeroMemory(NewSplit, sizeof(VMM_EPT_DYNAMIC_SPLIT));


    // Point back to the entry in the dynamic split for easy reference for which entry that dynamic split is for.
    NewSplit->Entry = TargetEntry;

    // Make a template for RWX 
    EntryTemplate.AsUInt = 0;
    EntryTemplate.ReadAccess = 1;
    EntryTemplate.WriteAccess = 1;
    EntryTemplate.ExecuteAccess = 1;

    // Copy the template into all the PML1 entries 
    __stosq((SIZE_T*)&NewSplit->PML1[0], EntryTemplate.AsUInt, VMM_EPT_PML1E_COUNT);


    // Set the page frame numbers for identity mapping.
    for (EntryIndex = 0; EntryIndex < VMM_EPT_PML1E_COUNT; EntryIndex++)
    {
        // Convert the 2MB page frame number to the 4096 page entry number plus the offset into the frame. 
        NewSplit->PML1[EntryIndex].PageFrameNumber = ((TargetEntry->PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + EntryIndex;
    }

    // Allocate a new pointer which will replace the 2MB entry with a pointer to 512 4096 byte entries. 
    NewPointer.AsUInt = 0;
    NewPointer.WriteAccess = 1;
    NewPointer.ReadAccess = 1;
    NewPointer.ExecuteAccess = 1;
    NewPointer.PageFrameNumber = (SIZE_T)VirtualToPhysicalAddress(&NewSplit->PML1[0]) / PAGE_SIZE;

    // Add our allocation to the linked list of dynamic splits for later deallocation 
    InsertHeadList(&EptPageTable->DynamicSplitList, &NewSplit->DynamicSplitList);

    // Now, replace the entry in the page table with our new split pointer.
    RtlCopyMemory(TargetEntry, &NewPointer, sizeof(NewPointer));

    return TRUE;
}

BOOLEAN EptHandleEptViolation(ULONG ExitQualification, UINT64 GuestPhysicalAddr)
{

    VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification;

    DbgBreakPoint();

    ViolationQualification.AsUInt = ExitQualification;

    if (EptHandlePageHookExit(ViolationQualification, GuestPhysicalAddr))
    {
        // Handled by page hook code.
        return TRUE;
    }

    LogError("Unexpected EPT violation");
    DbgBreakPoint();

    // Redo the instruction that caused the exception. 
    return FALSE;
}

VOID EptHandleMisconfiguration(UINT64 GuestAddress)
{
    LogInfo("EPT Misconfiguration!");
    LogError("A field in the EPT paging structure was invalid, Faulting guest address : 0x%llx", GuestAddress);

    DbgBreakPoint();
    // We can't continue now. 
    // EPT misconfiguration is a fatal exception that will probably crash the OS if we don't get out now.
}

BOOLEAN EptPageHook(PVOID TargetFunc, BOOLEAN HasLaunched) {

    ULONG LogicalCoreIndex;
    PVOID PreAllocBuff;
    LogicalCoreIndex = KeGetCurrentProcessorIndex();

    // See whether we allocated anything before (sth like an unused buffer)
    if (g_GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer == NULL)
    {
        PreAllocBuff = ExAllocatePoolWithTag(NonPagedPool, sizeof(VMM_EPT_DYNAMIC_SPLIT), POOLTAG);

        if (!PreAllocBuff)
        {
            LogError("Insufficient memory for pre-allocated buffer");
            return FALSE;
        }

        // Zero out the memory
        RtlZeroMemory(PreAllocBuff, sizeof(VMM_EPT_DYNAMIC_SPLIT));

        // Save the pre-allocated buffer
        g_GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer = PreAllocBuff;
    }

    if (HasLaunched)
    {
        if (AsmVmxVmcall(VMCALL_EXEC_HOOK_PAGE, TargetFunc, NULL, NULL, NULL) == STATUS_SUCCESS)
        {
            LogInfo("Hook applied from VMX Root Mode");

            if (!g_GuestState[LogicalCoreIndex].IsOnVmxRootMode)
            {
                // Now we have to notify all the core to invalidate their EPT
                HvNotifyAllToInvalidateEpt();
            }
            else
            {
                LogError("Tried to apply ept hook from root mode but logical core was in non-root mode.");
            }

            return TRUE;
        }
    }
    else
    {
        if (EptVmxRootModePageHook(TargetFunc, HasLaunched) == TRUE) {
            LogInfo("[*] Hook applied (VM has not launched)");
            return TRUE;
        }
    }

    LogWarning("Hook not applied");

    return FALSE;
}

BOOLEAN EptHandlePageHookExit(VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification, UINT64 GuestPhysicalAddr)
{
    SIZE_T PhysicalAddress;
    PVOID VirtualTarget;

    PEPT_PML1_ENTRY TargetPage;


    /* Translate the page from a physical address to virtual so we can read its memory.
       This function will return NULL if the physical address was not already mapped in
       virtual memory.
    */
    PhysicalAddress = PAGE_ALIGN(GuestPhysicalAddr);

    if (!PhysicalAddress)
    {
        LogError("Target address could not be mapped to physical memory");
        return FALSE;
    }

    TargetPage = EptGetPml1Entry(g_EptState->EptPageTable, PhysicalAddress);

    // Ensure the target is valid. 
    if (!TargetPage)
    {
        LogError("Failed to get PML1 entry for target address");
        return FALSE;
    }

    // If the violation was due to trying to execute a non-executable page, that means that the currently
    // swapped in page is our original RW page. We need to swap in the hooked executable page (fake page)
    if (!ViolationQualification.EptExecutable && ViolationQualification.ExecuteAccess)
    {

        TargetPage->ExecuteAccess = 1;

        // InveptAllContexts();
        INVEPT_DESCRIPTOR Descriptor;

        Descriptor.EptPointer = g_EptState->EptPointer.AsUInt;
        Descriptor.Reserved = 0;
        AsmInvept(1, &Descriptor);

        // Redo the instruction 
        g_GuestState[KeGetCurrentProcessorNumber()].IncrementRip = FALSE;

        LogInfo("Set the Execute Access of a page (PFN = 0x%llx) to 1", TargetPage->PageFrameNumber);

        return TRUE;
    }

    LogError("Invalid page swapping logic in hooked page");

    return FALSE;
}

BOOLEAN EptVmxRootModePageHook(PVOID TargetFunc, BOOLEAN HasLaunched)
{
    EPT_PML1_ENTRY OriginalEntry;
    INVEPT_DESCRIPTOR Descriptor;
    SIZE_T PhysicalAddress;
    PVOID VirtualTarget;
    PVOID TargetBuffer;
    PEPT_PML1_ENTRY TargetPage;
    ULONG LogicalCoreIndex;

    // Check whether we are in VMX Root Mode or Not 
    LogicalCoreIndex = KeGetCurrentProcessorIndex();

    if (g_GuestState[LogicalCoreIndex].IsOnVmxRootMode && g_GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer == NULL && HasLaunched)
    {
        return FALSE;
    }

    /* Translate the page from a physical address to virtual so we can read its memory.
     * This function will return NULL if the physical address was not already mapped in
     * virtual memory.
     */
    VirtualTarget = PAGE_ALIGN(TargetFunc);

    PhysicalAddress = (SIZE_T)VirtualToPhysicalAddress(VirtualTarget);

    if (!PhysicalAddress)
    {
        LogError("Target address could not be mapped to physical memory");
        return FALSE;
    }

    // Set target buffer
    TargetBuffer = g_GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer;


    if (!EptSplitLargePage(g_EptState->EptPageTable, TargetBuffer, PhysicalAddress, LogicalCoreIndex))
    {
        LogError("Could not split page for the address : 0x%llx", PhysicalAddress);
        return FALSE;
    }

    // Pointer to the page entry in the page table. 
    TargetPage = EptGetPml1Entry(g_EptState->EptPageTable, PhysicalAddress);

    // Ensure the target is valid. 
    if (!TargetPage)
    {
        LogError("Failed to get PML1 entry of the target address");
        return FALSE;
    }

    // Save the original permissions of the page 
    OriginalEntry = *TargetPage;

    /*
     * Lastly, mark the entry in the table as no execute. This will cause the next time that an instruction is
     * fetched from this page to cause an EPT violation exit. This will allow us to swap in the fake page with our
     * hook.
     */
    OriginalEntry.ReadAccess = 1;
    OriginalEntry.WriteAccess = 1;
    OriginalEntry.ExecuteAccess = 0;


    // Apply the hook to EPT 
    TargetPage->AsUInt = OriginalEntry.AsUInt;

    // Invalidate the entry in the TLB caches so it will not conflict with the actual paging structure.
    if (HasLaunched)
    {
        // Uncomment in order to invalidate all the contexts
        // LogInfo("INVEPT Results : 0x%x\n", InveptAllContexts());
        Descriptor.EptPointer = g_EptState->EptPointer.AsUInt;
        Descriptor.Reserved = 0;
        AsmInvept(1, &Descriptor);
    }

    return TRUE;
}

/* Invoke the Invept instruction */
unsigned char Invept(UINT32 Type, INVEPT_DESCRIPTOR* Descriptor)
{
    if (!Descriptor)
    {
        INVEPT_DESCRIPTOR ZeroDescriptor = { 0 };
        Descriptor = &ZeroDescriptor;
    }

    return AsmInvept(Type, Descriptor);
}

/* Invalidates all contexts in ept cache table */
unsigned char InveptAllContexts()
{
    return Invept(InveptAllContext, NULL);
}

/* Invalidates a single context in ept cache table */
unsigned char InveptSingleContexts(UINT64 EptPointer)
{
    INVEPT_DESCRIPTOR Descriptor = { EptPointer, 0 };

    return Invept(InveptSingleContext, &Descriptor);
}
