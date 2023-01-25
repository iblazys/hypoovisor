#pragma once
#include <ntddk.h>
#include <wdf.h> // BYTE

int MathPower(int Base, int Exponent);
BOOLEAN IsBitSet(SIZE_T BitField, SIZE_T BitPosition);
VOID SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set);
VOID GetBit(PVOID Addr, UINT64 Bit);

