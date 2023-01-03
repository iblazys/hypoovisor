#ifndef UTILS_H
#define UTILS_H
#include <ntddk.h>

/// <summary>
/// 
/// </summary>
int MathPower(int Base, int Exponent);

/// <summary>
/// Converts a virtual address to a physical address...
/// </summary>
UINT64 VirtualToPhysicalAddress(void* Va);

/// <summary>
/// Converts a physical address to a virtual address...
/// </summary>
PVOID PhysicalToVirtualAddress(UINT64 Pa);

#endif