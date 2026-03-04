#include <Arduino.h>
#include <ChaCha.h>
#include <string.h>

// Benchmark parameters - simulating real PrivacyLRS usage
const uint32_t PACKET_SIZE = 13;        // 13-byte packets
const uint32_t PACKETS_PER_SEC = 250;   // 250 Hz update rate
const uint32_t TEST_DURATION_SEC = 10;  // Run for 10 seconds
const uint32_t TOTAL_PACKETS = PACKETS_PER_SEC * TEST_DURATION_SEC;

// Test data
uint8_t test_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
uint8_t test_nonce[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
uint8_t test_counter[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

ChaCha cipher12(12);
ChaCha cipher20(20);

void runBenchmark(ChaCha &cipher, const char* name) {
    Serial.println("\n========================================");
    Serial.print("Benchmarking ");
    Serial.println(name);
    Serial.println("========================================");
    Serial.print("Packet size: ");
    Serial.print(PACKET_SIZE);
    Serial.println(" bytes");
    Serial.print("Target rate: ");
    Serial.print(PACKETS_PER_SEC);
    Serial.println(" packets/sec");
    Serial.print("Test duration: ");
    Serial.print(TEST_DURATION_SEC);
    Serial.println(" seconds");
    Serial.print("Total packets: ");
    Serial.println(TOTAL_PACKETS);
    Serial.println();

    // Initialize cipher
    cipher.setKey(test_key, 32);
    cipher.setIV(test_nonce, 8);
    cipher.setCounter(test_counter, 8);

    uint8_t plaintext[PACKET_SIZE];
    uint8_t ciphertext[PACKET_SIZE];
    for (int i = 0; i < PACKET_SIZE; i++) {
        plaintext[i] = i;
    }

    // Warm-up
    Serial.println("Warming up...");
    for (int i = 0; i < 100; i++) {
        cipher.encrypt(ciphertext, plaintext, PACKET_SIZE);
        yield();
    }

    // Benchmark: Measure time for all encryptions
    Serial.println("Running benchmark...");
    uint32_t start_time = micros();

    for (uint32_t i = 0; i < TOTAL_PACKETS; i++) {
        cipher.encrypt(ciphertext, plaintext, PACKET_SIZE);

        // Yield to watchdog every 100 packets
        if (i % 100 == 0) {
            yield();
        }
    }

    uint32_t end_time = micros();
    uint32_t total_time_us = end_time - start_time;

    // Calculate metrics
    float total_time_sec = total_time_us / 1000000.0f;
    float avg_time_us = (float)total_time_us / (float)TOTAL_PACKETS;
    float max_packets_per_sec = 1000000.0f / avg_time_us;

    // CPU usage calculation
    // At 250 Hz, each packet has 1/250 = 4000 us available
    float time_per_packet_slot_us = 1000000.0f / PACKETS_PER_SEC;
    float cpu_usage_percent = (avg_time_us / time_per_packet_slot_us) * 100.0f;

    // Results
    Serial.println("\n========================================");
    Serial.println("RESULTS:");
    Serial.println("========================================");
    Serial.print("Total time: ");
    Serial.print(total_time_sec, 3);
    Serial.println(" seconds");

    Serial.print("Average encryption time: ");
    Serial.print(avg_time_us, 2);
    Serial.println(" microseconds");

    Serial.print("Maximum throughput: ");
    Serial.print((uint32_t)max_packets_per_sec);
    Serial.println(" packets/sec");

    Serial.print("\nCPU usage at 250 Hz: ");
    Serial.print(cpu_usage_percent, 2);
    Serial.println("%");

    Serial.print("CPU time per second: ");
    Serial.print((avg_time_us * PACKETS_PER_SEC) / 1000.0f, 2);
    Serial.println(" ms");

    Serial.print("Idle time per second: ");
    Serial.print(1000.0f - ((avg_time_us * PACKETS_PER_SEC) / 1000.0f), 2);
    Serial.println(" ms");

    Serial.println("========================================\n");
}

// -------------------------------------------------------
// CollectEntropy() hardware validation
//
// Mirrors the Finding 8 fix in tx_main.cpp.
// RSSI source is zeroed (no radio in this standalone test);
// the hardware RNG and ChaCha20 KDF paths are exercised.
// -------------------------------------------------------

static void collectEntropyStandalone(uint8_t *outrnd, size_t len)
{
    uint8_t raw[32] = {0};

    // Hardware RNG (ESP32 on-chip TRNG)
    for (size_t i = 0; i < sizeof(raw); ) {
        uint32_t hw = esp_random();
        for (int b = 0; b < 4 && i < sizeof(raw); b++, i++)
            raw[i] ^= (uint8_t)(hw >> (b * 8));
    }

    // ChaCha20 KDF conditioning (same as production CollectEntropy)
    const uint8_t zeros[32] = {0};
    ChaCha kdf(20);
    kdf.setKey(raw, sizeof(raw));
    kdf.setIV(zeros, 8);
    kdf.encrypt(outrnd, zeros, len);

    memset(raw, 0, sizeof(raw));
}

static void printHex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Serial.print("0");
        Serial.print(buf[i], HEX);
        Serial.print(" ");
    }
    Serial.println();
}

void runEntropyTests()
{
    Serial.println("\n\n================================================");
    Serial.println("*   CollectEntropy() Hardware Validation Test  *");
    Serial.println("* (RSSI zeroed - no radio; HW RNG + KDF tested)*");
    Serial.println("================================================");

    bool all_pass = true;

    // Test 1: esp_random() returns a non-zero value
    Serial.println("\n[T1] esp_random() non-zero ...");
    uint32_t r = esp_random();
    Serial.print("  Value: 0x"); Serial.println(r, HEX);
    if (r != 0) {
        Serial.println("  PASS");
    } else {
        Serial.println("  WARN: returned 0 (possible but rare - re-run if seen repeatedly)");
    }

    // Test 2: 10 consecutive esp_random() calls produce varied output
    Serial.println("\n[T2] esp_random() varies across 10 calls ...");
    uint32_t samples[10];
    samples[0] = esp_random();
    bool allSame = true;
    for (int i = 1; i < 10; i++) {
        samples[i] = esp_random();
        if (samples[i] != samples[0]) allSame = false;
    }
    Serial.print("  Samples: ");
    for (int i = 0; i < 10; i++) { Serial.print("0x"); Serial.print(samples[i], HEX); Serial.print(" "); }
    Serial.println();
    if (!allSame) {
        Serial.println("  PASS");
    } else {
        Serial.println("  FAIL: all 10 values identical");
        all_pass = false;
    }

    // Test 3: CollectEntropy output is non-zero
    Serial.println("\n[T3] CollectEntropy() output non-zero ...");
    uint8_t out1[24] = {0};
    collectEntropyStandalone(out1, 24);
    Serial.print("  Output: "); printHex(out1, 24);
    bool nonZero = false;
    for (int i = 0; i < 24; i++) if (out1[i] != 0) { nonZero = true; break; }
    Serial.println(nonZero ? "  PASS" : "  FAIL: all-zeros output");
    if (!nonZero) all_pass = false;

    // Test 4: Two successive calls produce different output
    Serial.println("\n[T4] Two CollectEntropy() calls differ ...");
    uint8_t out2[24] = {0};
    collectEntropyStandalone(out2, 24);
    Serial.print("  Output: "); printHex(out2, 24);
    bool differs = (memcmp(out1, out2, 24) != 0);
    Serial.println(differs ? "  PASS" : "  FAIL: identical outputs");
    if (!differs) all_pass = false;

    // Test 5: ChaCha20 KDF is deterministic - same key -> same output
    Serial.println("\n[T5] ChaCha20 KDF deterministic (same key -> same output) ...");
    const uint8_t fixed_key[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
    };
    const uint8_t zeros[32] = {0};
    uint8_t kdf_a[24], kdf_b[24];
    ChaCha k1(20), k2(20);
    k1.setKey(fixed_key, 32); k1.setIV(zeros, 8); k1.encrypt(kdf_a, zeros, 24);
    k2.setKey(fixed_key, 32); k2.setIV(zeros, 8); k2.encrypt(kdf_b, zeros, 24);
    bool det = (memcmp(kdf_a, kdf_b, 24) == 0);
    Serial.println(det ? "  PASS" : "  FAIL: same key produced different output");
    if (!det) all_pass = false;

    // Test 6: Different keys produce different KDF output
    Serial.println("\n[T6] Different keys produce different KDF output ...");
    uint8_t flipped_key[32];
    memcpy(flipped_key, fixed_key, 32);
    flipped_key[0] ^= 0xFF;
    uint8_t kdf_c[24];
    ChaCha k3(20);
    k3.setKey(flipped_key, 32); k3.setIV(zeros, 8); k3.encrypt(kdf_c, zeros, 24);
    bool diffKeys = (memcmp(kdf_a, kdf_c, 24) != 0);
    Serial.println(diffKeys ? "  PASS" : "  FAIL: different keys produced same output");
    if (!diffKeys) all_pass = false;

    // Test 7: Bit distribution over ~1000 bytes of entropy output (~50% ones expected)
    Serial.println("\n[T7] Bit distribution over 1008 bytes (~50% ones expected) ...");
    int ones = 0;
    const int ROUNDS = 42;  // 42 * 24 = 1008 bytes
    for (int round = 0; round < ROUNDS; round++) {
        uint8_t buf[24];
        collectEntropyStandalone(buf, 24);
        for (int i = 0; i < 24; i++)
            for (int b = 0; b < 8; b++)
                if (buf[i] & (1 << b)) ones++;
        yield();
    }
    int total_bits = ROUNDS * 24 * 8;
    float ratio = (float)ones / (float)total_bits * 100.0f;
    Serial.print("  Ones: "); Serial.print(ones); Serial.print(" / "); Serial.println(total_bits);
    Serial.print("  Ratio: "); Serial.print(ratio, 1); Serial.println("% (expect 40-60%)");
    bool goodDist = (ratio > 40.0f && ratio < 60.0f);
    Serial.println(goodDist ? "  PASS" : "  FAIL: distribution far from 50%");
    if (!goodDist) all_pass = false;

    Serial.println("\n================================================");
    Serial.println(all_pass ? "ENTROPY TESTS: ALL PASSED" : "ENTROPY TESTS: FAILURES DETECTED");
    Serial.println("================================================");
}

void setup() {
    Serial.begin(115200);
    delay(3000);  // Give time for serial monitor

    Serial.println("\n\n");
    Serial.println("************************************************");
    Serial.println("*   ChaCha12 vs ChaCha20 Performance Test     *");
    Serial.println("*   Simulating PrivacyLRS Real-World Usage    *");
    Serial.println("************************************************");
    Serial.println();
    Serial.print("ESP32 CPU Frequency: ");
    Serial.print(getCpuFrequencyMhz());
    Serial.println(" MHz");
    Serial.println();

    // Test ChaCha12 (current production)
    runBenchmark(cipher12, "ChaCha12 (Production)");

    delay(2000);

    // Test ChaCha20 (RFC 8439 standard)
    runBenchmark(cipher20, "ChaCha20 (RFC 8439)");

    Serial.println("\n************************************************");
    Serial.println("*              BENCHMARK COMPLETE              *");
    Serial.println("************************************************");

    // CollectEntropy() hardware validation (Finding 8 fix)
    runEntropyTests();

    Serial.println("\nSystem will now loop. Reset to run again.\n");
}

void loop() {
    static uint32_t last_print = 0;
    if (millis() - last_print > 10000) {
        last_print = millis();
        Serial.println("Benchmark complete. Reset to run again.");
    }
}
