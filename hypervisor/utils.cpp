#include "utils.h"
#include <intrin.h>
#include "msr.h"

// Move me to better location
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
