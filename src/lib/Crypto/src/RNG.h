/*
 * RNG.h stub for PrivacyLRS
 *
 * The full rweather RNG class is not used in PrivacyLRS. CollectEntropy()
 * provides all randomness. This stub satisfies the #include in Curve25519.cpp
 * (which uses RNG.rand() only inside dh1(), which we do not call).
 *
 * If dh1() is ever called accidentally, rand() forwards to CollectEntropy()
 * so the key material is still high-quality rather than all-zeros.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

// Forward declaration; CollectEntropy() is defined in tx_main.cpp / rx_main.cpp
extern void CollectEntropy(uint8_t *outrnd, size_t len);

class RNGClass
{
public:
    void rand(void *data, size_t len)
    {
        CollectEntropy(static_cast<uint8_t *>(data), len);
    }
};

extern RNGClass RNG;
