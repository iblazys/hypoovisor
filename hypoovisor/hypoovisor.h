#pragma once

#ifndef HYPOOVISOR_H
#define HYPOOVISOR_H

#include <ntddk.h>
#include <ia32.h>
#include <intrin.h>

#include "shared.h"

#include "processor.h"

// This file is essentially our VMM - Virtual Machine Manager
// TODO: Clean up this file.

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096
#define VMM_STACK_SIZE      0x8000

// Hyper-V Shit
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS 0x40000000
#define HYPERV_CPUID_INTERFACE                0x40000001
#define HYPERV_CPUID_VERSION                  0x40000002
#define HYPERV_CPUID_FEATURES                 0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO         0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS         0x40000005

#define HYPERV_HYPERVISOR_PRESENT_BIT 0x80000000
#define HYPERV_CPUID_MIN              0x40000005
#define HYPERV_CPUID_MAX              0x4000ffff

typedef struct _VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR
{
    PVOID PreAllocatedBuffer;		// As we can't use ExAllocatePoolWithTag in VMX Root mode, this holds a pre-allocated buffer address
                                    // PreAllocatedBuffer == 0 indicates that it's not previously allocated
} VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR, * PVMX_NON_ROOT_MODE_MEMORY_ALLOCATOR;

typedef struct _VMX_VMXOFF_STATE
{
    BOOLEAN IsVmxoffExecuted;					// Shows whether the VMXOFF executed or not
    UINT64  GuestRip;							// Rip address of guest to return
    UINT64  GuestRsp;							// Rsp address of guest to return

} VMX_VMXOFF_STATE, * PVMX_VMXOFF_STATE;

typedef struct _VIRTUAL_MACHINE_STATE
{
    BOOLEAN IsOnVmxRootMode;							// Detects whether the current logical core is on Executing on VMX Root Mode
    BOOLEAN IncrementRip;								// Checks whether it has to redo the previous instruction or not (it used mainly in Ept routines)

    UINT64 VmxonRegionPhysicalAddress;					// Vmxon region physical address
    UINT64 VmxonRegionVirtualAddress;					// VMXON region virtual address
    UINT64 VmcsRegionPhysicalAddress;					// VMCS region physical address
    UINT64 VmcsRegionVirtualAddress;					// VMCS region virtual address
    UINT64 MsrBitmapVirtualAddress;                     // MSR Bitmap Virtual Address
    UINT64 MsrBitmapPhysicalAddress;                    // MSR Bitmap Physical Address

    EPT_POINTER* Eptp;                                  // Extended-Page-Table Pointer
    UINT64 VmmStack;                                    // Stack for VMM in VM-Exit State
    VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR PreAllocatedMemoryDetails; // The details of pre-allocated memory
    VMX_VMXOFF_STATE VmxoffState;

} VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

enum SEGREGS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
};

typedef enum
{
    REGION_VMCS,
    REGION_VMXON
} REGIONTYPE;

/**
typedef struct _GUEST_REGS
{
    ULONG64 rax; // 0x00         // NOT VALID FOR SVM
    ULONG64 rcx;
    ULONG64 rdx; // 0x10
    ULONG64 rbx;
    ULONG64 rsp; // 0x20         // rsp is not stored here on SVM
    ULONG64 rbp;
    ULONG64 rsi; // 0x30
    ULONG64 rdi;
    ULONG64 r8; // 0x40
    ULONG64 r9;
    ULONG64 r10; // 0x50
    ULONG64 r11;
    ULONG64 r12; // 0x60
    ULONG64 r13;
    ULONG64 r14; // 0x70
    ULONG64 r15;
} GUEST_REGS, * PGUEST_REGS;
*/

typedef void (*PFUNC)(IN ULONG ProcessorID, IN EPT_POINTER* EPTP);

UINT64 g_GuestRSP;
UINT64 g_GuestRIP;

extern UINT64 g_VirtualGuestMemoryAddress;

// ASM Functions - clean this shit up
extern void inline AsmEnableVmxOperation(void);
extern NTSTATUS inline  AsmVmxVmcall(unsigned long long VmcallNumber, unsigned long long OptionalParam1, unsigned long long OptionalParam2, unsigned long long OptionalParam3);
extern unsigned char inline AsmInvept(unsigned long Type, void* Descriptors);
extern void inline AsmVmxoffAndRestoreState();
extern void inline AsmSaveStateForVmxoff();

extern void AsmReloadGdtr(void* GdtBase, unsigned long GdtLimit);
extern void AsmReloadIdtr(void* GdtBase, unsigned long GdtLimit);

extern void AsmVMXSaveState();
extern void AsmVMXRestoreState();
extern void AsmVmexitHandler();

extern ULONG64 MSRRead(ULONG32 reg);
extern void MSRWrite(ULONG32 reg, ULONG64 MsrValue);

// shouldnt these be extern??
USHORT GetCs(VOID);
USHORT GetDs(VOID);
USHORT GetEs(VOID);
USHORT GetSs(VOID);
USHORT GetFs(VOID);
USHORT GetGs(VOID);
USHORT GetLdtr(VOID);
USHORT GetTr(VOID);
USHORT GetIdtLimit(VOID);
USHORT GetGdtLimit(VOID);
extern ULONG64 GetRflags(VOID);
UINT32 __load_ar(VOID);

BOOLEAN InitializeHV();
BOOLEAN StopHV();

BOOLEAN VMXTerminate();
VOID VMXVmxOff();

VOID FixCr4AndCr0Bits();
BOOLEAN LaunchVm(PVOID GuestStack);
VOID ResumeToNextInstruction();
VOID VmResumeInstruction();

// handlers - vmxhandlers.c ?
BOOLEAN MainVmexitHandler(PGUEST_REGS GuestRegs);
VOID HandleMSRRead(PGUEST_REGS GuestRegs);
VOID HandleMSRWrite(PGUEST_REGS GuestRegs);

// Hypoo functions, move these?
VOID HvInvalidateEptByVmcall(UINT64 Context);
VOID HvNotifyAllToInvalidateEpt();

#endif


