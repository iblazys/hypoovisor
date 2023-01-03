#include "ept.h"
#include "vmx.h"
#include "mem.h"

namespace ept 
{
	/// <summary>
	/// EPT Stuff, split this function up
	/// </summary>
	/// <returns></returns>
	UINT64 InitializeEptp()
	{
		// Ensure that the calling thread runs at an IRQL low enough to permit paging.
		PAGED_CODE();


        // Allocate EPT Extended-Page-Table Pointer and zero it out
        PEPTP EPTPointer = reinterpret_cast<PEPTP>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG));

        if (!EPTPointer)
            return NULL;

        RtlZeroMemory(EPTPointer, PAGE_SIZE);


        //  Allocate EPT PML4 and zero it out
        PEPT_PML4 EptPml4 = reinterpret_cast<PEPT_PML4>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG));

        if (!EptPml4)
        {
            // Free the EPTPointer if it fails
            ExFreePoolWithTag(EPTPointer, POOLTAG);
            return NULL;
        }

        RtlZeroMemory(EptPml4, PAGE_SIZE);

        //  Allocate EPT Page-Directory-Pointer-Table
        PEPDPTE EptPdpt = reinterpret_cast<PEPDPTE>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG));
        if (!EptPdpt)
        {
            ExFreePoolWithTag(EptPml4, POOLTAG);
            ExFreePoolWithTag(EPTPointer, POOLTAG);
            return NULL;
        }

        RtlZeroMemory(EptPdpt, PAGE_SIZE);

        //  Allocate EPT Page-Directory
        PEPDE EptPd = reinterpret_cast<PEPDE>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG));

        if (!EptPd)
        {
            ExFreePoolWithTag(EptPdpt, POOLTAG);
            ExFreePoolWithTag(EptPml4, POOLTAG);
            ExFreePoolWithTag(EPTPointer, POOLTAG);
            return NULL;
        }

        RtlZeroMemory(EptPd, PAGE_SIZE);

        //  Allocate EPT Page-Table
        PEPTE EptPt = reinterpret_cast<PEPTE>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG));

        if (!EptPt)
        {
            ExFreePoolWithTag(EptPd, POOLTAG);
            ExFreePoolWithTag(EptPdpt, POOLTAG);
            ExFreePoolWithTag(EptPml4, POOLTAG);
            ExFreePoolWithTag(EPTPointer, POOLTAG);
            return NULL;
        }

        RtlZeroMemory(EptPt, PAGE_SIZE);

        //
        // Setup Page Tables by allocating two pages Continuously
        // We allocate two pages because we need 1 page for our RIP to start and 1 page for RSP 1 + 1 = 2
        //
        const int PagesToAllocate = 10;
        UINT64    GuestMemory = reinterpret_cast<UINT64>(ExAllocatePoolWithTag(NonPagedPool, static_cast<SIZE_T>(PagesToAllocate) * PAGE_SIZE, POOLTAG));
        RtlZeroMemory((PVOID)GuestMemory, PagesToAllocate * PAGE_SIZE);

        for (size_t i = 0; i < PagesToAllocate; i++)
        {
            EptPt[i].Accessed = 0;
            EptPt[i].Dirty = 0;
            EptPt[i].MemoryType = 6;
            EptPt[i].ExecuteAccess = 1;
            EptPt[i].UserModeExecute = 0;
            EptPt[i].IgnorePat = 0;
            EptPt[i].PageFrameNumber = (mem::VirtualToPhysicalAddress(&GuestMemory + (i * PAGE_SIZE)) / PAGE_SIZE);
            EptPt[i].ReadAccess = 1;
            EptPt[i].SuppressVe = 0;
            EptPt[i].WriteAccess = 1;
        }

        // Setting up the Page Directory Entry
        EptPd->Accessed = 0;
        EptPd->ExecuteAccess = 1;
        EptPd->UserModeExecute = 0;
        EptPd->PageFrameNumber = (mem::VirtualToPhysicalAddress(EptPt) / PAGE_SIZE);
        EptPd->ReadAccess = 1;
        EptPd->Reserved1 = 0;
        EptPd->Reserved2 = 0; 
        EptPd->Reserved3 = 0; // correct ?
        EptPd->Reserved4 = 0; // correct ?
        EptPd->WriteAccess = 1;

        // Setting up the Page Table Entry
        EptPdpt->Accessed = 0;
        EptPdpt->ExecuteAccess = 1;
        EptPdpt->UserModeExecute = 0;
        EptPdpt->PageFrameNumber = (mem::VirtualToPhysicalAddress(EptPd) / PAGE_SIZE);
        EptPdpt->ReadAccess = 1;
        EptPdpt->Reserved1 = 0;
        EptPdpt->Reserved2 = 0;
        EptPdpt->Reserved3 = 0;
        EptPdpt->Reserved4 = 0;
        EptPdpt->WriteAccess = 1;

        // Setting up PML4E
        EptPml4->Accessed = 0;
        EptPml4->ExecuteAccess = 1;
        EptPml4->UserModeExecute = 0;
        EptPml4->PageFrameNumber = (mem::VirtualToPhysicalAddress(EptPdpt) / PAGE_SIZE);
        EptPml4->ReadAccess = 1;
        EptPml4->Reserved1 = 0;
        EptPml4->Reserved2 = 0;
        EptPml4->Reserved3 = 0;
        EptPml4->Reserved4 = 0;
        EptPml4->WriteAccess = 1;

        // Setting up the EPT pointer
        EPTPointer->EnableAccessAndDirtyFlags = 1;
        EPTPointer->MemoryType = 6; // 6 = Write-back (WB)
        EPTPointer->PageWalkLength = 3; // 4 (tables walked) - 1 = 3
        EPTPointer->PageFrameNumber = (mem::VirtualToPhysicalAddress(EptPml4) / PAGE_SIZE);
        EPTPointer->Reserved1 = 0;
        EPTPointer->Reserved2 = 0;

        DbgPrint("[*] Extended Page Table Pointer allocated at %llx", EPTPointer);
        return (UINT64)EPTPointer;
	}
}
