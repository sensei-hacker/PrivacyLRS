# Encryption tests

These tests run the real `lib/OtaCrypto` and `lib/Crypto` code, using separate TX and RX instances and the real CRC. They don't use a copy of the firmware's logic.

```
pio test -e native -f test_encryption
```

## What they cover

- The ChaCha20 known-answer vector
- Encrypting and decrypting both packet sizes, with packet type bits left readable
- Rejecting unencrypted packets and packets using the wrong key
- Recovering immediately from any burst of packet loss, and from 50% random loss
- Recovering from RX reboots, TX reboots, a stopped RX timer and rate changes
- Nonce and rolling wraps
- Counters never repeating across wraps, rate changes and reboots
- Uplink and telemetry never sharing keystream
- Decrypting telemetry with an epoch captured before a nonce wrap

## What they don't cover

The code in `tx_main.cpp` and `rx_main.cpp`, including radio timing and whether both ends really agree on `OtaNonce`. That needs testing on hardware: see `ENCRYPTION_RELIABILITY.md` in the repository root.
