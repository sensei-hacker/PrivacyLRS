# Finding #4: Secure Logging Macro Design

**Date:** 2025-12-02
**Designer:** Security Analyst / Cryptographer

---

## Design Objective

Create a secure logging macro that:
- Only logs cryptographic keys when explicitly enabled via build flag
- Defaults to OFF (production safe)
- Shows clear compile-time warning when enabled
- Zero runtime cost when disabled
- Drop-in replacement for DBGLN()

---

## Macro Design

### Name: `DBGLN_KEY()`

**Rationale:**
- Clear purpose: "DEBUG LOG KEY"
- Consistent with existing `DBGLN()` naming
- Easy to search/audit (`grep DBGLN_KEY`)
- Obvious what it does

---

## Build Flag Design

### Flag Name: `ALLOW_KEY_LOGGING`

**Rationale:**
- Explicit and self-documenting
- Hard to enable accidentally
- Clear intent: "I explicitly allow key logging"
- Positive assertion (not double-negative)

**Usage:**
```bash
# Enable key logging (debug only)
pio run -e <target> -DALLOW_KEY_LOGGING=1

# Production build (default - no flag)
pio run -e <target>
```

---

## Implementation

### Header Location

**Option 1:** Add to `src/include/encryption.h` ✅ **RECOMMENDED**
- Already encryption-specific
- Included by files that need it
- Logical grouping

**Option 2:** Create new `src/include/secure_logging.h`
- More modular
- Could grow if we add other secure logging types
- Requires additional include in rx_main.cpp

**Decision:** Use `encryption.h` for simplicity

---

### Macro Definition

```cpp
// In src/include/encryption.h

#ifdef ALLOW_KEY_LOGGING
  // WARNING: This enables cryptographic key logging for debugging
  // NEVER use in production builds - keys will be visible in logs!
  #define DBGLN_KEY(...) DBGLN(__VA_ARGS__)
  #warning "CRYPTOGRAPHIC KEY LOGGING ENABLED - DO NOT USE IN PRODUCTION!"
#else
  // Production default: keys never logged
  #define DBGLN_KEY(...) ((void)0)
#endif
```

**Design features:**
1. `#ifdef ALLOW_KEY_LOGGING` - only active when flag set
2. `DBGLN_KEY(...) DBGLN(__VA_ARGS__)` - pass-through to standard logging
3. `#warning` - compiler emits visible warning during build
4. `((void)0)` - no-op that doesn't generate code (zero cost)
5. Variadic `...` - accepts any number of arguments like printf

---

## Usage Pattern

### Before (Insecure):
```cpp
DBGLN("master_key = %d, %d, %d, %d", master_key[0], master_key[1], master_key[2], master_key[3]);
```

### After (Secure):
```cpp
DBGLN_KEY("master_key = %d, %d, %d, %d", master_key[0], master_key[1], master_key[2], master_key[3]);
```

**Benefits:**
- Minimal code change (just rename macro)
- Clear intent (this logs sensitive data)
- Safe by default (production builds silent)
- Explicit opt-in (must set build flag)

---

## Compile-Time Behavior

### Production Build (Default - Flag OFF)

**Build command:**
```bash
pio run -e Unified_ESP32_RX_via_WIFI
```

**Preprocessor expansion:**
```cpp
// This line:
DBGLN_KEY("master_key = %d", master_key[0]);

// Expands to:
((void)0);  // Complete no-op, optimized out entirely
```

**Result:**
- ✅ No code generated
- ✅ Zero runtime cost
- ✅ No keys in logs
- ✅ No compiler warning

---

### Debug Build (Flag ON)

**Build command:**
```bash
pio run -e Unified_ESP32_RX_via_WIFI -DALLOW_KEY_LOGGING=1
```

**Compiler output:**
```
Compiling .pio/build/.../src/rx_main.cpp.o
src/include/encryption.h:35:2: warning: "CRYPTOGRAPHIC KEY LOGGING ENABLED - DO NOT USE IN PRODUCTION!" [-W#warnings]
#warning "CRYPTOGRAPHIC KEY LOGGING ENABLED - DO NOT USE IN PRODUCTION!"
```

**Preprocessor expansion:**
```cpp
// This line:
DBGLN_KEY("master_key = %d", master_key[0]);

// Expands to:
DBGLN("master_key = %d", master_key[0]);
```

**Result:**
- ✅ Keys appear in logs
- ✅ Compiler warns loudly
- ✅ Debugging enabled
- ⚠️ NOT SAFE FOR PRODUCTION

---

## Alternative Designs Considered

### Alternative 1: Runtime Check
```cpp
#define DBGLN_KEY(...) do { if (DEBUG_KEYS_ENABLED) DBGLN(__VA_ARGS__); } while(0)
```

**Rejected because:**
- Runtime cost (branch check)
- Requires runtime variable
- Code still compiled in (larger binary)
- Less secure (could be enabled accidentally)

**Our design is better:** Compile-time elimination

---

### Alternative 2: Separate Function
```cpp
void log_key(const char *format, ...) {
  #ifdef ALLOW_KEY_LOGGING
    // va_list implementation
  #endif
}
```

**Rejected because:**
- More complex
- Function call overhead
- Need to implement va_list handling
- Less familiar to developers

**Our design is better:** Simple macro

---

### Alternative 3: Multiple Security Levels
```cpp
DBGLN_SECRET()   // Never logs even with flag
DBGLN_PRIVATE()  // Logs only with special flag
DBGLN_KEY()      // Logs with ALLOW_KEY_LOGGING
```

**Rejected because:**
- Over-engineered
- Current need is simple: keys yes/no
- Can add later if needed

**Our design is better:** YAGNI (You Aren't Gonna Need It)

---

## Documentation Requirements

### Code Comments

**In encryption.h:**
```cpp
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
```

### README / Developer Guide

**Add section to README.md:**
```markdown
## Debugging Encryption (Developer Guide)

### Logging Cryptographic Keys

By default, cryptographic keys are NEVER logged (even in debug builds).

To enable key logging for debugging:

1. Add build flag: `-DALLOW_KEY_LOGGING=1`
2. Rebuild
3. Look for compiler warning: "CRYPTOGRAPHIC KEY LOGGING ENABLED"
4. Keys will appear in debug output

**CRITICAL:** Never use this flag in production builds!
- Keys are secret material
- Logging compromises security
- Only for local development/debugging
```

---

## Security Considerations

### Defense in Depth

**This fix provides:**
1. ✅ Compile-time protection (default OFF)
2. ✅ Explicit opt-in required (can't enable accidentally)
3. ✅ Visible warning (compiler alerts developer)
4. ✅ Code review visibility (DBGLN_KEY obvious in diffs)

**This fix does NOT provide:**
- Runtime protection (once compiled with flag, keys will log)
- Encryption of logged keys
- Automatic redaction

**Acceptable because:** This is a debug tool, not production code

### Attack Surface

**Reduced risk:**
- Production builds: impossible to leak keys via this path
- Debug builds: developer must explicitly enable
- Code review: DBGLN_KEY is obvious in PRs

**Remaining risk:**
- Developer could enable flag and ship production build
- Mitigation: CI/CD should never set ALLOW_KEY_LOGGING
- Mitigation: Documentation warns against production use

---

## Testing Strategy

### Test 1: Production Build (Flag OFF)

**Command:**
```bash
pio run -e native
```

**Expected:**
- ✅ Compiles without warning
- ✅ No keys in output
- ✅ Encryption works normally

**Verification:**
```bash
# Run and check output
pio test -e native
# Expected: No "master_key" or "session key" in output
```

---

### Test 2: Debug Build (Flag ON)

**Command:**
```bash
pio run -e native -DALLOW_KEY_LOGGING=1
```

**Expected:**
- ⚠️ Compiler warning: "CRYPTOGRAPHIC KEY LOGGING ENABLED"
- ✅ Keys appear in output
- ✅ Encryption works normally

**Verification:**
```bash
# Build and look for warning
pio run -e native -DALLOW_KEY_LOGGING=1 2>&1 | grep "KEY LOGGING"

# Run and check output
pio test -e native -DALLOW_KEY_LOGGING=1
# Expected: "master_key", "session key" visible in output
```

---

### Test 3: Code Size Impact

**Verify no production overhead:**
```bash
# Build without flag
pio run -e Unified_ESP32_RX_via_WIFI
ls -l .pio/build/Unified_ESP32_RX_via_WIFI/firmware.bin

# Build with flag
pio run -e Unified_ESP32_RX_via_WIFI -DALLOW_KEY_LOGGING=1
ls -l .pio/build/Unified_ESP32_RX_via_WIFI/firmware.bin

# Expected: Same size (or negligible difference)
```

---

## Implementation Checklist

**Phase 3 tasks:**
- [ ] Add macro to `src/include/encryption.h`
- [ ] Add documentation comments
- [ ] Replace rx_main.cpp:464 (encrypted session key)
- [ ] Replace rx_main.cpp:465 (master key)
- [ ] Replace rx_main.cpp:485-486 (decrypted session key)
- [ ] Update README.md with debugging section

**Phase 4 tasks:**
- [ ] Test production build (flag OFF)
- [ ] Test debug build (flag ON)
- [ ] Verify compiler warning
- [ ] Verify code size impact
- [ ] Test on hardware (optional)

---

## Design Decision Summary

| Aspect | Decision | Rationale |
|--------|----------|-----------|
| **Macro name** | `DBGLN_KEY()` | Clear, consistent with DBGLN |
| **Build flag** | `ALLOW_KEY_LOGGING` | Explicit, hard to enable accidentally |
| **Implementation** | Compile-time ifdef | Zero runtime cost |
| **Header** | `encryption.h` | Logical grouping |
| **Warning** | `#warning` directive | Visible compile-time alert |
| **Default** | OFF (disabled) | Production safe |
| **Documentation** | Inline + README | Developers informed |

---

## Conclusion

**This design provides:**
- ✅ Simple implementation (< 10 lines of code)
- ✅ Zero production overhead
- ✅ Strong default security (flag OFF)
- ✅ Clear developer experience (compiler warning)
- ✅ Easy to audit (`grep DBGLN_KEY`)

**Ready for Phase 3 implementation.**

---

**Phase 2 Complete: 2025-12-02**
