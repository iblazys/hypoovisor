#ifndef UTILS_H
#define UTILS_H

#include <ntddk.h>
#include <wdf.h> // BYTE

typedef struct _NT_KPROCESS
{
	DISPATCHER_HEADER Header;
	LIST_ENTRY ProfileListHead;
	ULONG_PTR DirectoryTableBase;
	UCHAR Data[1];
}NT_KPROCESS, * PNT_KPROCESS;

int MathPower(int Base, int Exponent);
BOOLEAN IsBitSet(SIZE_T BitField, SIZE_T BitPosition);
VOID SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set);
VOID GetBit(PVOID Addr, UINT64 Bit);
UINT64 FindSystemDirectoryTableBase();

#endif