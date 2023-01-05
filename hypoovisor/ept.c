#include "ept.h"
#include "memory.h"

UINT64 InitializeEPTP()
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