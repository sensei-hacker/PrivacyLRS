#pragma once

#ifdef USE_ENCRYPTION

#include <climits>
#include "targets.h"

#define stringify_literal(x) # x
#define stringify_expanded(x) stringify_literal(x)

// DBGLN_KEY() - Secure logging for cryptographic keys
//
// This macro is disabled by default (production safe).
// Keys are NEVER logged unless explicitly enabled via build flag.
//
// To enable (debugging only):
//   pio run -e <target> -DALLOW_KEY_LOGGING=1
//
// WARNING: NEVER enable in production builds!
// Logged keys can compromise the entire encryption system.
//
// Usage:
//   DBGLN_KEY("session_key = %x %x %x", key[0], key[1], key[2]);
//
#ifdef ALLOW_KEY_LOGGING
  // WARNING: This enables cryptographic key logging for debugging
  // NEVER use in production builds - keys will be visible in logs!
  #define DBGLN_KEY(...) DBGLN(__VA_ARGS__)
  #warning "CRYPTOGRAPHIC KEY LOGGING ENABLED - DO NOT USE IN PRODUCTION!"
#else
  // Production default: keys never logged
  #define DBGLN_KEY(...) ((void)0)
#endif

typedef enum : uint8_t {
    ENCRYPTION_STATE_NONE,
    ENCRYPTION_STATE_DH_SENT,   // TX has sent DH init, waiting for RX response
    ENCRYPTION_STATE_PROPOSED,  // Legacy: used during DH response processing
    ENCRYPTION_STATE_FULL,
    ENCRYPTION_STATE_DISABLED
} encryptionState_e;

typedef struct encryption_params_s
{
    uint8_t nonce[8];
    uint8_t key[16];

} encryption_params_t;

// DH handshake packet (48 bytes): Curve25519 public key + 16-byte HMAC-SHA256 auth tag.
// Sent by both TX (MSP_ELRS_INIT_ENCRYPT) and RX (MSP_ELRS_DH_RESPONSE).
typedef struct dh_handshake_s
{
    uint8_t pub[32];  // Curve25519 ephemeral public key
    uint8_t mac[16];  // HKDF-SHA256(master_key, pub, "auth")[0:16]
} dh_handshake_t;    // 48 bytes total

bool ICACHE_RAM_ATTR DecryptMsg(uint8_t *input);
void ICACHE_RAM_ATTR EncryptMsg(uint8_t *input, uint8_t *output);

// Entropy collection — defined in common.cpp, callable from TX and RX
void CollectEntropy(uint8_t *outrnd, size_t len);

// ECDH helpers — defined in common.cpp
void generate_dh_keypair(uint8_t pub[32], uint8_t priv[32]);
void compute_dh_mac(uint8_t mac[16], const uint8_t *master_key,
                    size_t master_key_len, const uint8_t pub[32]);
bool verify_dh_mac(const uint8_t *master_key, size_t master_key_len,
                   const uint8_t pub[32], const uint8_t mac[16]);
void derive_session_key(encryption_params_t *params, const uint8_t shared[32],
                        const uint8_t tx_pub[32], const uint8_t rx_pub[32]);
bool apply_session_key(encryption_params_t *params);

/// in: valid chars are 0-9 + A-F + a-f
/// out_len_max==0: convert until the end of input string, out_len_max>0 only convert this many numbers
/// returns actual out size
int hexStr2Arr(unsigned char* out, const char* in, size_t out_len_max = 0);

#endif
