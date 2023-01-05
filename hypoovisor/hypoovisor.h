#pragma once
#include <ntddk.h>
#include <ia32.h>
#include <intrin.h>

// This file is essentially our VMM - Virtual Machine Manager

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096
#define VMM_STACK_SIZE      0x8000

#define POOLTAG 0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS) - Change ME

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion; // VMXON region
    UINT64 VmcsRegion;  // VMCS region
    UINT64 Eptp;              // Extended-Page-Table Pointer
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

UINT64 g_StackPointerForReturning;
UINT64 g_BasePointerForReturning;

extern VIRTUAL_MACHINE_STATE *g_GuestState;
extern UINT64 g_VirtualGuestMemoryAddress;
extern int g_ProcessorCounts;


// ASM Functions
extern void inline AsmEnableVmxOperation(void);
extern void inline AsmVmxoffAndRestoreState();
extern void inline AsmSaveStateForVmxoff();
extern void AsmVmexitHandler();

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

// move these to memory.c ?
BOOLEAN AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN AllocateVmcsRegion(IN VIRTUAL_MACHINE_STATE* GuestState);

// move to a vmx.c file ?
VOID LaunchVm(int ProcessorID, EPT_POINTER* EPTP);
VOID TerminateVmx();
VOID MainVmexitHandler(PGUEST_REGS GuestRegs);
VOID ResumeToNextInstruction();
VOID VmResumeInstruction();


