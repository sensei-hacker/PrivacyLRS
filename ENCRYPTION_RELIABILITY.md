# Encryption reliability: issues found and changes made

**Branch:** `stateless_encryption`, based on `secure_01_fixes` at `149836b5`
**Base firmware:** ExpressLRS 3.5.3 → sensei-hacker/PrivacyLRS → hsergei/PrivacyLRS

## Summary

The encryption made the control link fail permanently in situations stock ExpressLRS recovers from: 4 lost packets in a row, a receiver reboot, or a packet rate change. It also stayed unencrypted in some cases without telling the pilot, and its master key could be guessed.

This change replaces the session key and running counter with stateless encryption, so a packet can be decrypted without knowing anything about earlier packets. It also derives the key properly from the binding phrase.

**This has had only basic hardware testing.** On a RadioMaster Pocket and a BETAFPV 2.4GHz AIO RX, the main recovery tests passed and it survived a short flight. It has not had a long soak test or been flown at the edge of range, so treat it as beta. See [Hardware test results](#hardware-test-results).

## Issues found

Line numbers refer to `149836b5`, under `src/`.

### Link reliability

| # | Issue | Where | What happened | Status |
|---|---|---|---|---|
| R1 | Small counter window | `src/common.cpp:280` | The RX only tried counter offsets +0 to +3 and -1, and nothing could reset them. 4 lost packets in a row broke the link until the radio rebooted. | Fixed |
| R2 | RX reboot never recovered | `src/tx_main.cpp:1776` | The TX never left the encrypted state, and a rebooted RX had no key. It stayed disconnected until the radio rebooted. | Fixed |
| R3 | TX reboot left the link unencrypted | `src/rx_main.cpp:1219` | The RX kept encrypting telemetry with the old key. The TX couldn't read it, so it never reached "connected" and never re-keyed. Sticks kept working, unencrypted and without telemetry. | Fixed |
| R4 | Packet rate change could break the link | `src/tx_main.cpp:737` | The RX switched after the first sync, then ended up 4 behind against a limit of 3. Found by tracing the code, not confirmed on hardware. | Fixed |
| R5 | Key exchange race | `src/rx_main.cpp:1359`, `src/tx_main.cpp:395` | The RX switched to encryption before the TX did. The acknowledgement only got through if it went out in the roughly 200 µs before the RX main loop ran. If not, the TX stayed stuck, with sticks unencrypted and no telemetry. | Fixed |
| R6 | TX could encrypt without the RX having a key | `src/tx_main.cpp:1786`, `lib/StubbornSender/stubborn_sender.cpp:100` | On a weak link or an RX reboot during the exchange, the sender timed out to idle. The TX treated that as success and began encrypting. | Fixed |
| R7 | Uninitialized pointer at full-resolution rates | `src/common.cpp:307` | `otaPktPtr` was only set for 8-byte packets, so 100 Full and 333 Full used an uninitialized pointer. | Fixed |
| R8 | More CPU time and more false accepts | `src/common.cpp:282` | A corrupt packet cost up to 5 decrypts inside the interrupt, and had 5 chances to pass the CRC by luck. | Fixed |
| R9 | Crypto not in IRAM | `lib/Crypto/src/ChaCha.cpp` | The ChaCha code ran from flash inside the radio interrupt. | Fixed |

How long the old design lasted before permanent loss, from a simulation of its counter logic. These are medians and include the 2.5–4 s disconnect timeout. They assume independent random loss, which is the best case; bursty loss was much worse.

| Rate | Fatal gap | LQ 95 | LQ 90 | LQ 80 |
|---|---|---|---|---|
| F1000 | 4 ms | ~2 min | ~10 s | ~3 s |
| F500 | 8 ms | ~4 min | ~12 s | ~4 s |
| 250Hz | 16 ms | ~8 min | ~34 s | ~5 s |
| 150Hz | 27 ms | ~13 min | ~51 s | ~9 s |
| 50Hz | 80 ms | >30 min | ~4 min | ~17 s |

### Security

| # | Issue | Where | What happened | Status |
|---|---|---|---|---|
| S1 | Weak master key | `python/build_flags.py:75-79` | The key was a hash of the 6-byte UID, not the phrase, so it had 48 bits at most. UID bytes 3–5 were sent unencrypted, leaving at most 24 unknown bits. Anyone who recorded a power-up could brute force the session key. | Fixed |
| S2 | UID was a fast hash of the phrase | `python/build_flags.py:42` | MD5 of the phrase goes over the air in the UID, which would let an attacker test phrase guesses quickly even with a slow KDF. | Fixed |
| S3 | Keystream reuse | `src/common.cpp:252` | Both directions shared one counter, so any lost packet made the TX and RX encrypt with the same keystream. At 250Hz and LQ 95, the simulation showed 13 of 234 telemetry packets affected per minute. | Fixed |
| S4 | Unencrypted packets accepted | `src/rx_main.cpp:1219` | The result of `DecryptMsg` was ignored, so a valid unencrypted packet was accepted while encrypted. | Fixed |
| S5 | Key messages could be replayed | `src/rx_main.cpp:1354` | Replaying an old key message would make the RX switch to a wrong key and lose the link. | Fixed (no key messages now) |
| S6 | ChaCha12, not ChaCha20 | `src/tx_main.cpp:330`, `src/rx_main.cpp:506` | The "ChaCha20 upgrade" was overridden by `rounds = 12`. This was a false claim rather than a practical weakness. | Fixed |
| S7 | Unprocessed RSSI used as randomness | `src/tx_main.cpp:234` | Session keys came straight from radio RSSI bits with no hashing. | Fixed (no random keys now) |
| S8 | Key printed in build logs | `python/build_flags.py:81` | Every build printed the master key. The first fix removed one print but missed the `build flags:` line, so the key kept being printed until that line was filtered too. | Fixed |
| S9 | Telemetry off meant no encryption | `src/tx_main.cpp:1776` | The key exchange needs telemetry, so with telemetry off nothing was encrypted, with no warning. | Fixed |

### Tests

The old `test/test_encryption/test_encryption.cpp` contained its own copy of `EncryptMsg` and `DecryptMsg`, using a different algorithm from the firmware, with `success = true` in place of the CRC check. Its passing "482 lost packets" test said nothing about the firmware. **Replaced.**

### Other findings, not changed

The `origin/security/ecdh-forward-secrecy` branch doesn't fix any of the reliability issues above, and its handshake appears to deadlock when run over the air. The RX encrypts its reply (`rx_main.cpp:681` on that branch), but the TX needs that reply before it can decrypt (`tx_main.cpp:303`, `:1664`). This comes from reading the code; it hasn't been run. Key generation would also stop RC output on an ESP8285 for at least 256 ms.

## What changed

### Stateless encryption (new `lib/OtaCrypto`)

Each packet's keystream comes from a counter that both ends can always recover:

```
[direction:8][bootCount:16][rolling:16][OtaNonce:8]
```

| Field | Purpose | How the RX gets it |
|---|---|---|
| `OtaNonce` | Existing slot counter. Advances whether or not a packet arrived. | Timer, corrected by sync packets as in stock |
| `rolling` | Extends the 8-bit nonce. Advances on each wrap or reset. | Tracks wraps itself, corrected by sync packets |
| `bootCount` | Saved in TX flash and advances each boot, so reboots can't reuse keystream. | Sync packets |
| `direction` | Keeps uplink and telemetry keystreams apart. | Fixed per direction |

Other changes to how packets are handled:
- **No handshake:** `InitCrypto`, `CryptoSetKeys`, `DecryptMsg`, `MSP_ELRS_INIT_ENCRYPT`, the encryption states and `include/encryption.h` are all removed.
- **Sync packets are unencrypted, as in stock.** The 2 packet-type bits of every packet are also unencrypted, so the RX knows what it received before decrypting.
- **Sync packet layout:** `UID3` and `UID4` now carry half of the counter, alternating between `rolling` and `bootCount`. The top bit of `UID5` says which one. The RX therefore needs two syncs after a reboot.
- **Sync packets reject bad data less well than stock.** The UID bytes in `UID3` and `UID4` are gone, leaving the 14-bit CRC and one bit of `UID5`, so about 1 in 131072 random packets passes, against about 1 in 17 billion in stock. Changing the CRC seed can't help, because a random packet passes a 14-bit CRC at the same rate whatever the seed.
- **`OtaSyncGuard` protects a working link from those packets.** While the RX is connected and has decoded a non-sync packet in the last 250 ms, it ignores a sync whose nonce, FHSS index, packet rate or counter disagree with its own, unless a second sync asks for the same rate. The TX sends several syncs for a rate change, so that still works, with one fewer spare sync. Once packets stop arriving every sync is believed, so recovery isn't slowed. A disconnected or tentative RX isn't protected, and can still act on a false sync.
- **Telemetry:** the TX saves the epoch and nonce in `HandlePrepareForTLM`, which is the same slot the RX encrypts from.
- **ChaCha20 with a 256-bit key.** The ChaCha functions now run from IRAM, confirmed in the ESP8285 ELF. IRAM grew by 664 bytes.
- **`OTA_VERSION_ID`** differs from stock on encrypted builds, so encrypted and stock devices can't partly connect. Handsets still see the stock version number.
- **`bootCount` storage:** in NVS on ESP32, and in its own EEPROM slot elsewhere, so a config reset doesn't touch it. It's written at boot before the radio starts.

How each failure now recovers:

| Event | Recovery |
|---|---|
| Any packet loss | The next packet decrypts normally |
| Long fade or failsafe | Syncs restore the nonce and high bits, then normal reconnect |
| RX reboot | Key is compiled in, so it needs two syncs |
| TX reboot | New `bootCount` arrives by sync |
| Packet rate change | Stock sync spam; `rolling` is sent first after a nonce reset |
| Telemetry off | Still encrypted, as no two-way exchange is needed |

### Key derivation (`python/build_flags.py`)

- **The phrase is what counts now.** PBKDF2-HMAC-SHA256 with 1,000,000 iterations turns the full phrase into a 32-byte key plus the 6-byte UID. This takes about 0.3 s per build.
- **The UID comes from the same slow derivation,** so it can't be used as a shortcut for testing guesses. `build_flags.py` and `binary_configurator.py` share this code in `python/phrase_kdf.py`, so a device built with PlatformIO links to one configured by the Configurator.
- **The key is left out of the normal build output.** It's still passed to the compiler as a define, so it appears in verbose output (`pio run -v`) and in `compile_commands.json`. Don't share those. Logs from builds before this fix contain the key, so treat them as secret, or change the phrase if they've been shared.
- **Short phrases get a warning:** the build warns under 20 characters and fails only if the phrase is empty.

### Trade-offs

- **The binding phrase is now the only secret.** Without session keys, anyone who gets the phrase or key can read any recording, even without capturing a power-up. That includes anyone who reads the flash of a lost aircraft. A weak phrase can still be guessed, just more slowly.
- **No forward secrecy.** A leaked key exposes past recordings. See the next steps below.
- **Reconnects may be slightly slower** at standard rates, because the RX needs two syncs instead of one. This needs measuring.
- **Sync contents are visible,** as in stock. That reveals timing, link settings and the counter, but no stick or telemetry data.

### Known limitations

- **This provides confidentiality, not authentication.** There's still no message authentication, as in stock ELRS. An attacker can't read packets or forge sensible new ones without the key, but they can spoof sync packets to disrupt the link, flip bits in packets, and could replay old packets by rewinding the RX with a forged sync.
- **Keystream reuse is still possible after a full flash erase.** Erasing the flash resets `bootCount`, so old counter values come around again under the same phrase. **Use a new phrase after a full erase.** A corrupted NVS being erased has the same effect. The count also wraps after 65,536 boots.
- **Nonce slips in Hybrid mode:** stock RC packets survive the RX's nonce being off by one, but now they fail until the next sync. This matches how stock Wide mode already behaves, so it should be rare.
- **Flash writes:** one per TX boot.
- **Setting the phrase in the web UI breaks the link, and weakens it.** The web UI's phrase field (`html/scan.js`) still derives the UID with MD5, and the key can only be set at build time. Set the phrase at build time only, and always build the TX and RX from the same phrase.
- **Official release builds aren't encrypted.** Encryption needs a phrase at compile time, so a prebuilt image configured afterwards with `--phrase` gets a UID but no key. Check any image before flashing: `gzip -dc firmware.bin.gz | grep -c "expand 32-byte k"` prints `0` if it has no encryption.
- **`finding4-*.md` are out of date.** The `DBGLN_KEY` macro they describe was removed along with the session key code.

## Verification

### Done

| Check | Result |
|---|---|
| New encryption tests, running real `OtaCrypto` and `ChaCha` as a separate TX and RX with the real CRC | 25 of 25 pass, including 7 for `OtaSyncGuard` |
| ChaCha20 known-answer vector | Pass |
| Mutation checks: 5 deliberate bugs added to `OtaCrypto.cpp`, plus 2 in `OtaSyncGuard` | All caught |
| Other native tests | Pass, except `test_stubborn` and `test_msp_vtx`, which also error on the unmodified code |
| Builds with a phrase | ESP8285 RX, ESP32 TX, ESP8285 TX, ESP32 RX, ESP32 900 MHz TX, ESP32 LR1121 TX |
| Build without a phrase (ESP32 TX, ESP8285 RX) | Compile. The ESP8285 RX contains no crypto code |

The tests cover bursts of up to 100,000 lost packets, 50% random loss, RX and TX reboots, rate changes, nonce and rolling wraps, and counters never repeating.

### Hardware test results

Tested on a RadioMaster Pocket (ESP32 TX) and a BETAFPV 2.4GHz AIO RX (ESP8285), reported by the person who flashed them. The packet rates used weren't recorded. The tests in this first table were run before `OtaSyncGuard` was added.

| Test | Result |
|---|---|
| Connect and fly a short flight | Passed |
| Power-cycle the drone, leave the radio on | Passed |
| Cover the RX with a metal tin for 2 s, then remove it | Passed |
| Change packet rate in Lua | Passed |
| Reboot the radio, leave the drone on | Passed |
| Run 100 Full and 333 Full | Passed |

With `OtaSyncGuard` (commit `14044457`), on the same RadioMaster Pocket and BETAFPV 2.4GHz AIO RX at 10 mW, also reported by the person who flashed the build. The number of attempts wasn't recorded.

| Test | Result |
|---|---|
| Reconnect at LQ 35-40% (about 60% loss) | Passed |
| Change packet rate at LQ 35-40% | Passed |
| Reconnect at 50Hz | Passed, in roughly 1-2 s by eye. Not yet compared with stock |

### Tests still needed

| Test | Expected result |
|---|---|
| Repeat the first table's tests with `OtaSyncGuard`, including a short flight | Same results |
| Time reconnects against stock 3.5.3, especially at slow rates such as 50Hz | Close to stock, despite needing two syncs |
| 100 cold boots and 100 rate changes | No permanent link loss |
| Several hours of accumulated running | No drops or reboots |
| Measure decrypt time on the ESP8285 | Comfortably inside the 200 µs budget (`PACKET_TO_TOCK_SLACK`) |
| Fly at the edge of range, using an aircraft you can afford to lose | Same range and recovery as stock |

Telemetry off won't be tested, because private telemetry is one of the main reasons to use this firmware. The firmware doesn't block that setting, so a link with telemetry off remains untested on hardware.

## Upgrading

1. **Flash both the TX and RX from this branch, built with the same phrase.** They won't link to anything else, including older PrivacyLRS builds.
2. **Choose a new phrase of 5 or more random words.** It's now the only secret.
3. **Re-check your failsafe setup** before any flight.

## Building with ExpressLRS Configurator

Use Local mode, which compiles with your binding phrase. For an ESP8285 RX, `binary_configurator.py` now also writes `firmware.bin.gz` next to its input file, so the Configurator should offer a compressed file that the RX web UI accepts. It may be named `<target>.gz`, for example `betafpv.rx_2400.aio.wifi.gz`, with `firmware.bin.gz` beside it. ESP8285 TX targets still get a `.bin`, which is what their web UI expects.

Local mode overwrites `src/user_defines.txt` with your phrase, and writes `src/firmware.bin.gz`. Take care not to commit either file.

## Next steps

1. Finish the remaining hardware tests above.
2. Add forward secrecy for telemetry only, on its own branch. RC and sync would stay on the pre-shared key, so a failed handshake could never affect control. The handshake would only run while disarmed, and telemetry would fall back to the pre-shared key if it fails.
