# Finding #4: Key Logging Audit Report

**Date:** 2025-12-02
**Auditor:** Security Analyst / Cryptographer
**Scope:** PrivacyLRS codebase - all cryptographic key logging

---

## Executive Summary

**Total locations found:** 3 (all in rx_main.cpp)
**Severity:** HIGH (all locations leak cryptographic keys)
**Affected file:** `src/src/rx_main.cpp`

---

## Detailed Findings

### Location #1: Encrypted Session Key
**File:** `src/src/rx_main.cpp:464`
**Severity:** HIGH
**Code:**
```cpp
DBGLN("encrypted session key = %d, %d, %d, %d", params->key[0], params->key[1], params->key[2], params->key[3]);
```

**Analysis:**
- Logs first 4 bytes of encrypted session key
- While encrypted, this reveals ciphertext which could aid cryptanalysis
- Should use secure logging

---

### Location #2: Master Key
**File:** `src/src/rx_main.cpp:465`
**Severity:** CRITICAL
**Code:**
```cpp
DBGLN("master_key = %d, %d, %d, %d", master_key[0], master_key[1], master_key[2], master_key[3]);
```

**Analysis:**
- Logs first 4 bytes of PLAINTEXT master key
- **CRITICAL:** Master key is the root secret, compromise = total system compromise
- Partial key leak still weakens security significantly
- **MUST** use secure logging

---

### Location #3: Decrypted Session Key
**File:** `src/src/rx_main.cpp:485-486`
**Severity:** CRITICAL
**Code:**
```cpp
DBGLN("New key = dec: %d, %d, %d hex:  %x, %x, %x", params->key[0], params->key[1], params->key[2], params->key[3],
    params->key[4], params->key[5], params->key[6]);
```

**Analysis:**
- Logs first 7 bytes of PLAINTEXT session key (both decimal and hex)
- **CRITICAL:** Session key used to encrypt all subsequent packets
- Full compromise of communication if leaked
- **MUST** use secure logging

---

## TX Side Analysis

**File:** `src/src/tx_main.cpp`
**Result:** ✅ No key logging found

**Analysis:**
- TX side creates and encrypts session key (lines 297-321)
- No DBGLN statements logging keys
- TX side is secure

---

## Common Encryption Functions

**File:** `src/src/common.cpp`
**Result:** ✅ No key logging found

**Analysis:**
- EncryptMsg() and DecryptMsg() do not log keys
- Only commented-out debug statement (non-sensitive)
- Common functions are secure

---

## Risk Assessment

### Production Impact

**If keys leak in production:**
1. **Master key leak:** Complete system compromise
   - Attacker can decrypt all session keys
   - Attacker can impersonate transmitter
   - All communication compromised

2. **Session key leak:** Communication compromise
   - Attacker can decrypt current session
   - Must re-pair to get new session key
   - Single-session compromise

3. **Attack vectors:**
   - Serial console output (if connected)
   - Log files (if debug logging enabled)
   - Crash dumps (may contain log buffer)
   - Debug interfaces (JTAG, SWD with log access)

### Current State

**RISK:** HIGH
- All 3 logging statements use standard `DBGLN()`
- No build-time protection
- Keys will leak if debug logging enabled in production

---

## Recommendations

### Priority Actions

1. **Implement DBGLN_KEY() macro** (Phase 2)
   - Build flag controlled: `ALLOW_KEY_LOGGING`
   - Default: OFF (production safe)
   - Compile warning when enabled

2. **Replace all 3 locations** (Phase 3)
   - rx_main.cpp:464 → `DBGLN_KEY()`
   - rx_main.cpp:465 → `DBGLN_KEY()`
   - rx_main.cpp:485-486 → `DBGLN_KEY()`

3. **Verify no leaks** (Phase 4)
   - Test production build: NO keys visible
   - Test debug build: keys visible with warning

### Future Considerations

**Other sensitive data to review:**
- Counter values (less sensitive but worth protecting)
- Nonce values (already commented out at line 1104)
- Challenge/response values (if implemented)

**Secure logging pattern:**
- Use DBGLN_KEY() for ALL cryptographic material
- Document when to use vs DBGLN()
- Code review checklist item

---

## Summary Statistics

**Files scanned:** 3 (`rx_main.cpp`, `tx_main.cpp`, `common.cpp`)
**Total DBGLN statements:** 25
**Key logging statements:** 3 (12%)
**Files requiring changes:** 1 (`rx_main.cpp`)
**Lines requiring changes:** 3

**Fix complexity:** LOW
- Single header addition
- 3 line changes (DBGLN → DBGLN_KEY)
- High impact, minimal code change

---

## Next Steps

1. ✅ **Phase 1 Complete:** Audit finished (this document)
2. **Phase 2:** Design DBGLN_KEY() macro
3. **Phase 3:** Implement and replace
4. **Phase 4:** Test both modes
5. **Submit:** Completion report to Manager

---

**Phase 1 Complete: 2025-12-02**
