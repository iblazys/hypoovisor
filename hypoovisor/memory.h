#pragma once
#include <ntddk.h>
#include "hypoovisor.h"

/// <summary>
/// Allocates the VMM stack and zero the memory.
/// </summary>
/// <param name="ProcessorID"></param>
/// <returns></returns>
UINT64 AllocateVMMStack();

/// <summary>
/// Allocates the MSR bitmap and zero the memory.
/// </summary>
/// <param name="ProcessorID"></param>
/// <returns></returns>
UINT64 AllocateMSRBitmap();

/// <summary>
/// Converts a virtual address to a physical address...
/// </summary>
/// <param name="virtualAddress">the virtual address</param>
/// <returns>the physical address</returns>
UINT64 VirtualToPhysicalAddress(void* virtualAddress);

/// <summary>
/// Converts a physical address to a virtual address...
/// </summary>
/// <param name="physicalAddress">the physical address</param>
/// <returns>the virtual address</returns>
UINT64 PhysicalToVirtualAddress(UINT64 physicalAddress);

BOOLEAN AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE* GuestState);

