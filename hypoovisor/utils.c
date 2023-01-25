#include "utils.h"

int MathPower(int Base, int Exponent)
{
    int Result = 1;
    for (;;)
    {
        if (Exponent & 1)
        {
            Result *= Base;
        }

        Exponent >>= 1;
        if (!Exponent)
        {
            break;
        }
        Base *= Base;
    }
    return Result;
}

BOOLEAN IsBitSet(SIZE_T BitField, SIZE_T BitPosition)
{
    return (BitField >> BitPosition) & 1UL;
}

VOID SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set)
{
    PAGED_CODE();

    UINT64 Byte = Bit / 8;
    UINT64 Temp = Bit % 8;
    UINT64 N = 7 - Temp;

    BYTE* Addr2 = Addr;
    if (Set)
    {
        Addr2[Byte] |= (1 << N);
    }
    else
    {
        Addr2[Byte] &= ~(1 << N);
    }
}

VOID GetBit(PVOID Addr, UINT64 Bit)
{
    UINT64 Byte = 0, K = 0;
    Byte = Bit / 8;
    K = 7 - Bit % 8;
    BYTE* Addr2 = Addr;

    return Addr2[Byte] & (1 << K);
}
