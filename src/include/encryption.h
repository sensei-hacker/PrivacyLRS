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
  ENCRYPTION_STATE_PROPOSED,
  ENCRYPTION_STATE_FULL,
	ENCRYPTION_STATE_DISABLED
} encryptionState_e;

typedef struct encryption_params_s
{
    uint8_t nonce[8];
    uint8_t key[16];

} encryption_params_t;

bool ICACHE_RAM_ATTR DecryptMsg(uint8_t *input);
void ICACHE_RAM_ATTR EncryptMsg(uint8_t *input, uint8_t *output);

/// in: valid chars are 0-9 + A-F + a-f
/// out_len_max==0: convert until the end of input string, out_len_max>0 only convert this many numbers
/// returns actual out size
int hexStr2Arr(unsigned char* out, const char* in, size_t out_len_max = 0);

#endif
