#ifndef SHARED_H
#define SHARED_H

#include <ntddk.h>

//
// Contains structs, constants and enums shared between
//

#define POOLTAG		0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS) - TODO: Change ME

#define RPL_MASK	3

// System and User Ring Definitions
#define DPL_USER	3
#define DPL_SYSTEM	0

typedef struct _GUEST_REGS
{
	ULONG64 rax;                  // 0x00         
	ULONG64 rcx;
	ULONG64 rdx;                  // 0x10
	ULONG64 rbx;
	ULONG64 rsp;                  // 0x20         // rsp is not stored here
	ULONG64 rbp;
	ULONG64 rsi;                  // 0x30
	ULONG64 rdi;
	ULONG64 r8;                   // 0x40
	ULONG64 r9;
	ULONG64 r10;                  // 0x50
	ULONG64 r11;
	ULONG64 r12;                  // 0x60
	ULONG64 r13;
	ULONG64 r14;                  // 0x70
	ULONG64 r15;
} GUEST_REGS, * PGUEST_REGS;

typedef union _CR_FIXED
{
	UINT64 Flags;

	struct
	{
		unsigned long Low;
		long          High;

	} Fields;

} CR_FIXED, * PCR_FIXED;


//
// Crude Logging
//

// Types
typedef enum _LOG_TYPE
{
	LOG_INFO,
	LOG_WARNING,
	LOG_ERROR
}LOG_TYPE;

// Function
VOID LogPrintInfo(PCSTR Format);
VOID LogPrintWarning(PCSTR Format);
VOID LogPrintError(PCSTR Format);

// Defines
#define LogInfo(format, ...)  \
    LogPrintInfo("[+] Information (%s:%d) | " format "\n",	\
		 __FUNCTION__, __LINE__, __VA_ARGS__)

#define LogWarning(format, ...)  \
    LogPrintWarning("[-] Warning (%s:%d) | " format "\n",	\
		__FUNCTION__, __LINE__, __VA_ARGS__)

#define LogError(format, ...)  \
    LogPrintError("[!] Error (%s:%d) | " format "\n",	\
		 __FUNCTION__, __LINE__, __VA_ARGS__);	\
		DbgBreakPoint()

// Log without any prefix
#define Log(format, ...)  \
    LogPrintInfo(format "\n", __VA_ARGS__)

#endif