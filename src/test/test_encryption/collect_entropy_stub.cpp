// Native stub for CollectEntropy.
// Provides entropy from /dev/urandom (or rand() fallback) for native unit tests.
// The hardware-specific implementation lives in common.cpp (excluded from native builds).
#ifdef TARGET_NATIVE
#include <cstdint>
#include <cstdlib>
#include <cstdio>

void CollectEntropy(uint8_t *outrnd, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f)
    {
        (void)fread(outrnd, 1, len, f);
        fclose(f);
    }
    else
    {
        for (size_t i = 0; i < len; i++)
            outrnd[i] = (uint8_t)(rand() & 0xFF);
    }
}
#endif
