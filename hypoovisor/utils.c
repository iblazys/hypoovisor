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
