#pragma once
#include <ntddk.h>
#include <ia32.h>
#include <intrin.h>

#include "processor.h"

// This file is essentially our VMM - Virtual Machine Manager
// TODO: Clean up this file.

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096
#define VMM_STACK_SIZE      0x8000

#define POOLTAG 0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS) - TODO: Change ME
#define RPL_MASK    3

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

// System and User Ring Definitions
#define DPL_USER                3
#define DPL_SYSTEM              0

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion; // VMXON region
    UINT64 VmcsRegion;  // VMCS region
    EPT_POINTER* Eptp;              // Extended-Page-Table Pointer
    UINT64 VmmStack;          // Stack for VMM in VM-Exit State
    UINT64 MsrBitmap;         // MSR Bitmap Virtual Address
    UINT64 MsrBitmapPhysical; // MSR Bitmap Physical Address
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

typedef void (*PFUNC)(IN ULONG ProcessorID, IN EPT_POINTER* EPTP);

UINT64 g_GuestRSP;
UINT64 g_GuestRIP;

extern VIRTUAL_MACHINE_STATE *g_GuestState;
extern UINT64 g_VirtualGuestMemoryAddress;
extern int g_ProcessorCounts;

// ASM Functions
extern void inline AsmEnableVmxOperation(void);
extern void inline AsmVmxoffAndRestoreState();
extern void inline AsmSaveStateForVmxoff();
extern void inline VMXSaveState();
extern void inline VMXRestoreState();
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
ULONG64 GetRflags(VOID);
UINT32 __load_ar(VOID);

BOOLEAN InitializeHV();
BOOLEAN RunHV();
BOOLEAN StopHV();

BOOLEAN RunOnProcessor(ULONG ProcessorNumber, EPT_POINTER* EPTP, PFUNC Routine);
BOOLEAN TerminateVMXOnProcessor(ULONG ProcessorNumber);
VOID LaunchVm(int ProcessorID, EPT_POINTER* EPTP, PVOID GuestStack);
VOID TerminateVmx();
VOID ResumeToNextInstruction();
VOID VmResumeInstruction();

// handlers - vmxhandlers.c ?
BOOLEAN MainVmexitHandler(PGUEST_REGS GuestRegs);
BOOLEAN HandleCPUID(PGUEST_REGS state);
VOID HandleControlRegisterAccess(PGUEST_REGS GuestState);
VOID HandleMSRRead(PGUEST_REGS GuestRegs);
VOID HandleMSRWrite(PGUEST_REGS GuestRegs);


