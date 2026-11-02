/**
 * Tests for over-the-air encryption.
 *
 * These run the real OtaCrypto and ChaCha code with separate TX and RX instances, and
 * the real CRC, so a wrong keystream is detected the same way the firmware detects it.
 *
 * Not covered here, because it lives in tx_main.cpp and rx_main.cpp: radio timing, and
 * whether both ends really agree on OtaNonce. That needs testing on hardware.
 */

#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <tuple>
#include <vector>

#include <unity.h>

#include "crc.h"
#include "OtaCrypto.h"

#define PACKET_SIZE_STD 8U
#define PACKET_SIZE_FULL 13U
#define PACKET_TYPE_RC 0b00
#define PACKET_TYPE_TLM 0b11
#define CRC14_POLY 0x2E57
#define CRC_INIT 0x1234

static const uint8_t TEST_KEY[OTA_CRYPTO_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static Crc2Byte crc14;

// Same layout as OTA_Packet4_s: type in the low 2 bits of byte 0, 14-bit CRC split between
// the high 6 bits of byte 0 and the last byte.
static void addCrc(uint8_t *packet)
{
    packet[0] &= 0b11;
    const uint16_t crc = crc14.calc(packet, PACKET_SIZE_STD - 1, CRC_INIT);
    packet[0] |= (crc >> 8) << 2;
    packet[PACKET_SIZE_STD - 1] = crc;
}

static bool crcValid(const uint8_t *packet)
{
    uint8_t copy[PACKET_SIZE_STD];
    memcpy(copy, packet, sizeof(copy));
    const uint16_t received = ((uint16_t)(copy[0] >> 2) << 8) | copy[PACKET_SIZE_STD - 1];
    copy[0] &= 0b11;
    return crc14.calc(copy, PACKET_SIZE_STD - 1, CRC_INIT) == received;
}

static void makePacket(uint8_t *packet, uint8_t type, uint8_t seed)
{
    packet[0] = type;
    for (unsigned i = 1; i < PACKET_SIZE_STD - 1; ++i)
    {
        packet[i] = seed * 7 + i;
    }
    addCrc(packet);
}

/**
 * A TX and RX pair with the same structure as the firmware. Each has its own OtaNonce and its own
 * OtaCryptoSession, and they only share what goes over the air.
 */
struct SimTx
{
    OtaCryptoSession crypto;
    uint8_t nonce = 0;

    SimTx(uint16_t bootCount = 1)
    {
        crypto.init(TEST_KEY);
        crypto.setBootCount(bootCount);
    }

    void tick()
    {
        nonce++;
        if (nonce == 0)
        {
            crypto.onNonceWrapped();
        }
    }

    void resetNonce()
    {
        nonce = 0;
        crypto.onNonceReset();
    }
};

struct SimRx
{
    OtaCryptoSession crypto;
    uint8_t nonce = 0;

    SimRx() { crypto.init(TEST_KEY); }

    void tick()
    {
        nonce++;
        if (nonce == 0)
        {
            crypto.onNonceWrapped();
        }
    }

    void receiveSyncFrom(SimTx &tx)
    {
        uint8_t high, low;
        OtaCryptoSyncField_e field;
        tx.crypto.fillSync(&high, &low, &field);
        crypto.receiveSync(high, low, field, nonce, tx.nonce);
        nonce = tx.nonce;
    }
};

// The RX hears both sync fields, as it does when connecting
static void connect(SimTx &tx, SimRx &rx)
{
    rx.receiveSyncFrom(tx);
    rx.receiveSyncFrom(tx);
}

// One slot: the TX sends an RC packet, and the RX decodes it unless it was lost
static bool slot(SimTx &tx, SimRx &rx, bool lost = false, uint8_t seed = 0)
{
    tx.tick();
    rx.tick();

    uint8_t sent[PACKET_SIZE_STD];
    makePacket(sent, PACKET_TYPE_RC, seed);
    uint8_t air[PACKET_SIZE_STD];
    memcpy(air, sent, sizeof(air));
    tx.crypto.apply(air, sizeof(air), OTA_CRYPTO_UPLINK, tx.nonce);

    if (lost)
    {
        return false;
    }

    rx.crypto.apply(air, sizeof(air), OTA_CRYPTO_UPLINK, rx.nonce);
    return crcValid(air) && memcmp(air, sent, sizeof(air)) == 0;
}

void setUp(void)
{
    crc14.init(14, CRC14_POLY);
}

void tearDown(void) {}

/***** Cipher *****/

// Known answer for ChaCha20 with a 256-bit key and a 64-bit nonce, all zero
void test_chacha20_known_answer(void)
{
    static const uint8_t expected[32] = {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7};
    const uint8_t zero8[8] = {0};
    const uint8_t zero32[32] = {0};
    uint8_t out[32] = {0};

    ChaCha cipher(20);
    cipher.setKey(zero32, sizeof(zero32));
    cipher.setIV(zero8, sizeof(zero8));
    cipher.setCounter(zero8, sizeof(zero8));
    cipher.encrypt(out, out, sizeof(out));

    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out, sizeof(expected));
}

/***** Packet handling *****/

void test_roundtrip_std_and_full_size(void)
{
    OtaCryptoSession a, b;
    a.init(TEST_KEY);
    b.init(TEST_KEY);

    for (size_t len : {PACKET_SIZE_STD, PACKET_SIZE_FULL})
    {
        uint8_t plain[PACKET_SIZE_FULL], air[PACKET_SIZE_FULL];
        for (size_t i = 0; i < len; ++i)
        {
            plain[i] = i * 11 + 3;
        }
        memcpy(air, plain, len);
        a.apply(air, len, OTA_CRYPTO_UPLINK, 42);
        TEST_ASSERT_TRUE(memcmp(air + 1, plain + 1, len - 1) != 0);
        b.apply(air, len, OTA_CRYPTO_UPLINK, 42);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(plain, air, len);
    }
}

void test_packet_type_stays_readable(void)
{
    OtaCryptoSession a;
    a.init(TEST_KEY);
    for (uint8_t type = 0; type < 4; ++type)
    {
        for (unsigned nonce = 0; nonce < 256; ++nonce)
        {
            uint8_t packet[PACKET_SIZE_STD] = {type, 1, 2, 3, 4, 5, 6, 7};
            a.apply(packet, sizeof(packet), OTA_CRYPTO_UPLINK, nonce);
            TEST_ASSERT_EQUAL_UINT8(type, packet[0] & 0b11);
        }
    }
}

void test_unencrypted_packet_is_rejected(void)
{
    SimRx rx;
    unsigned accepted = 0;
    for (unsigned i = 0; i < 2000; ++i)
    {
        rx.tick();
        uint8_t packet[PACKET_SIZE_STD];
        makePacket(packet, PACKET_TYPE_RC, i);
        rx.crypto.apply(packet, sizeof(packet), OTA_CRYPTO_UPLINK, rx.nonce);
        accepted += crcValid(packet);
    }
    // Only by chance, about 1 in 16384 each
    TEST_ASSERT_LESS_OR_EQUAL_UINT(3, accepted);
}

void test_wrong_key_is_rejected(void)
{
    uint8_t otherKey[OTA_CRYPTO_KEY_SIZE];
    memcpy(otherKey, TEST_KEY, sizeof(otherKey));
    otherKey[31] ^= 1;
    OtaCryptoSession a, b;
    a.init(TEST_KEY);
    b.init(otherKey);

    unsigned accepted = 0;
    for (unsigned i = 0; i < 2000; ++i)
    {
        uint8_t packet[PACKET_SIZE_STD];
        makePacket(packet, PACKET_TYPE_RC, i);
        a.apply(packet, sizeof(packet), OTA_CRYPTO_UPLINK, i);
        b.apply(packet, sizeof(packet), OTA_CRYPTO_UPLINK, i);
        accepted += crcValid(packet);
    }
    TEST_ASSERT_LESS_OR_EQUAL_UINT(3, accepted);
}

/***** Packet loss: must never have any effect beyond the lost packets *****/

void test_any_burst_of_loss_recovers_immediately(void)
{
    // 4 was the burst that permanently broke the previous design
    for (unsigned burst : {1U, 3U, 4U, 5U, 50U, 255U, 256U, 257U, 5000U, 100000U})
    {
        SimTx tx;
        SimRx rx;
        connect(tx, rx);
        TEST_ASSERT_TRUE(slot(tx, rx));
        for (unsigned i = 0; i < burst; ++i)
        {
            slot(tx, rx, true);
        }
        TEST_ASSERT_TRUE_MESSAGE(slot(tx, rx), "first packet after the burst");
        TEST_ASSERT_TRUE(slot(tx, rx));
    }
}

void test_random_loss_never_causes_a_decode_failure(void)
{
    SimTx tx;
    SimRx rx;
    connect(tx, rx);
    uint32_t rng = 12345;
    for (unsigned i = 0; i < 200000; ++i)
    {
        rng = rng * 1103515245 + 12345;
        const bool lost = ((rng >> 16) & 0xff) < 128; // 50% loss
        const bool ok = slot(tx, rx, lost, i);
        if (!lost)
        {
            TEST_ASSERT_TRUE(ok);
        }
    }
}

/***** Reboots and reconnects *****/

void test_rx_reboot_recovers_from_two_syncs(void)
{
    SimTx tx(7);
    SimRx rx;
    connect(tx, rx);
    for (unsigned i = 0; i < 1000; ++i)
    {
        TEST_ASSERT_TRUE(slot(tx, rx));
    }

    // A rebooted RX knows only the key, as in the firmware
    SimRx rebooted;
    TEST_ASSERT_FALSE(slot(tx, rebooted));
    connect(tx, rebooted);
    TEST_ASSERT_TRUE(slot(tx, rebooted));
    TEST_ASSERT_TRUE(slot(tx, rebooted));
}

void test_tx_reboot_recovers_from_two_syncs(void)
{
    SimTx tx(7);
    SimRx rx;
    connect(tx, rx);
    for (unsigned i = 0; i < 1000; ++i)
    {
        TEST_ASSERT_TRUE(slot(tx, rx));
    }

    SimTx rebooted(8);
    TEST_ASSERT_FALSE(slot(rebooted, rx));
    connect(rebooted, rx);
    TEST_ASSERT_TRUE(slot(rebooted, rx));
}

void test_rx_with_stopped_timer_recovers_from_sync(void)
{
    SimTx tx;
    SimRx rx;
    connect(tx, rx);
    TEST_ASSERT_TRUE(slot(tx, rx));

    // The RX timer stops when it loses the link, so it misses several nonce wraps
    for (unsigned i = 0; i < 5000; ++i)
    {
        tx.tick();
    }

    connect(tx, rx);
    TEST_ASSERT_TRUE(slot(tx, rx));
}

void test_rate_change_recovers_from_first_sync(void)
{
    SimTx tx;
    SimRx rx;
    connect(tx, rx);
    TEST_ASSERT_TRUE(slot(tx, rx));

    // Whichever field was due next, the first sync after a reset must carry the new rolling value
    uint8_t high, low;
    OtaCryptoSyncField_e field;
    tx.crypto.fillSync(&high, &low, &field);

    tx.resetNonce();
    TEST_ASSERT_FALSE(slot(tx, rx));
    rx.receiveSyncFrom(tx);
    TEST_ASSERT_TRUE(slot(tx, rx));
}

void test_bootcount_only_sync_follows_small_nonce_slip_across_wrap(void)
{
    SimTx tx;
    SimRx rx;
    connect(tx, rx);
    for (unsigned i = 0; i < 254; ++i)
    {
        slot(tx, rx);
    }
    uint8_t high, low;
    OtaCryptoSyncField_e field;
    tx.crypto.fillSync(&high, &low, &field); // Next sync carries bootCount

    // The TX has crossed the wrap, and the RX has fallen behind just before it
    tx.tick();
    tx.tick();
    tx.tick();
    TEST_ASSERT_EQUAL_UINT8(1, tx.nonce);
    TEST_ASSERT_EQUAL_UINT8(254, rx.nonce);

    rx.receiveSyncFrom(tx);
    TEST_ASSERT_TRUE(slot(tx, rx));
}

/***** Nonce and rolling wraps *****/

void test_rolling_wrap_stays_in_step(void)
{
    SimTx tx;
    SimRx rx;
    connect(tx, rx);

    // Skip almost to the end of rolling on both ends
    uint8_t high = 0xff, low = 0xff;
    OtaCryptoSyncField_e rollingField = OTA_CRYPTO_SYNC_ROLLING;
    tx.crypto.receiveSync(high, low, rollingField, 0, 0);
    rx.crypto.receiveSync(high, low, rollingField, 0, 0);
    const uint16_t bootBefore = tx.crypto.getEpoch().bootCount;

    TEST_ASSERT_FALSE(tx.crypto.takeBootCountChanged());
    for (unsigned i = 0; i < 600; ++i)
    {
        TEST_ASSERT_TRUE(slot(tx, rx));
    }

    TEST_ASSERT_EQUAL_UINT16(bootBefore + 1, tx.crypto.getEpoch().bootCount);
    TEST_ASSERT_EQUAL_UINT16(bootBefore + 1, rx.crypto.getEpoch().bootCount);
    TEST_ASSERT_TRUE(tx.crypto.takeBootCountChanged());
    TEST_ASSERT_FALSE(tx.crypto.takeBootCountChanged());
}

/***** The keystream must never repeat *****/

static std::vector<uint8_t> keystream(OtaCryptoSession &session, OtaCryptoDirection_e direction, OtaCryptoEpoch_t epoch, uint8_t nonce)
{
    std::vector<uint8_t> out(PACKET_SIZE_FULL, 0);
    session.apply(out.data(), out.size(), direction, epoch, nonce);
    return out;
}

void test_every_counter_field_changes_the_keystream(void)
{
    OtaCryptoSession s;
    s.init(TEST_KEY);
    const OtaCryptoEpoch_t base = {1, 1};
    const auto reference = keystream(s, OTA_CRYPTO_UPLINK, base, 1);

    TEST_ASSERT_TRUE(reference == keystream(s, OTA_CRYPTO_UPLINK, base, 1));
    TEST_ASSERT_FALSE(reference == keystream(s, OTA_CRYPTO_DOWNLINK, base, 1));
    TEST_ASSERT_FALSE(reference == keystream(s, OTA_CRYPTO_UPLINK, base, 2));
    TEST_ASSERT_FALSE(reference == keystream(s, OTA_CRYPTO_UPLINK, OtaCryptoEpoch_t{1, 2}, 1));
    TEST_ASSERT_FALSE(reference == keystream(s, OTA_CRYPTO_UPLINK, OtaCryptoEpoch_t{2, 1}, 1));
}

// Follows the TX through nonce wraps, rate changes and reboots, and checks that it never
// uses the same counter twice. This is the property that the previous design lost.
void test_tx_never_reuses_a_counter(void)
{
    std::set<std::tuple<uint16_t, uint16_t, uint8_t>> used;
    uint16_t bootCount = 1;

    for (unsigned boot = 0; boot < 5; ++boot)
    {
        SimTx tx(bootCount++);
        for (unsigned rateChange = 0; rateChange < 5; ++rateChange)
        {
            for (unsigned i = 0; i < 1000; ++i)
            {
                tx.tick();
                const OtaCryptoEpoch_t epoch = tx.crypto.getEpoch();
                const bool isNew = used.insert(std::make_tuple(epoch.bootCount, epoch.rolling, tx.nonce)).second;
                TEST_ASSERT_TRUE(isNew);
            }
            tx.resetNonce();
        }
    }
}

void test_uplink_and_telemetry_never_share_keystream(void)
{
    OtaCryptoSession s;
    s.init(TEST_KEY);
    const OtaCryptoEpoch_t epoch = {3, 9};
    for (unsigned nonce = 0; nonce < 256; ++nonce)
    {
        TEST_ASSERT_FALSE(keystream(s, OTA_CRYPTO_UPLINK, epoch, nonce) == keystream(s, OTA_CRYPTO_DOWNLINK, epoch, nonce));
    }
}

/***** Sync fields *****/

void test_sync_alternates_between_rolling_and_bootcount(void)
{
    SimTx tx(0x1234);
    tx.crypto.receiveSync(0xab, 0xcd, OTA_CRYPTO_SYNC_ROLLING, 0, 0);

    uint8_t high, low;
    OtaCryptoSyncField_e field;

    tx.crypto.fillSync(&high, &low, &field);
    TEST_ASSERT_EQUAL(OTA_CRYPTO_SYNC_ROLLING, field);
    TEST_ASSERT_EQUAL_UINT8(0xab, high);
    TEST_ASSERT_EQUAL_UINT8(0xcd, low);

    tx.crypto.fillSync(&high, &low, &field);
    TEST_ASSERT_EQUAL(OTA_CRYPTO_SYNC_BOOTCOUNT, field);
    TEST_ASSERT_EQUAL_UINT8(0x12, high);
    TEST_ASSERT_EQUAL_UINT8(0x34, low);

    tx.crypto.fillSync(&high, &low, &field);
    TEST_ASSERT_EQUAL(OTA_CRYPTO_SYNC_ROLLING, field);
}

/***** Telemetry *****/

// The TX captures the epoch and nonce for telemetry before the slot, and they may have moved on
// by the time the packet arrives. This covers the case where that crosses a nonce wrap.
void test_telemetry_decodes_with_captured_epoch_across_wrap(void)
{
    SimTx tx;
    SimRx rx;
    connect(tx, rx);
    for (unsigned i = 0; i < 255; ++i)
    {
        TEST_ASSERT_TRUE(slot(tx, rx));
    }
    TEST_ASSERT_EQUAL_UINT8(255, tx.nonce);

    const OtaCryptoEpoch_t capturedEpoch = tx.crypto.getEpoch();
    const uint8_t capturedNonce = tx.nonce;

    uint8_t sent[PACKET_SIZE_STD], air[PACKET_SIZE_STD];
    makePacket(sent, PACKET_TYPE_TLM, 99);
    memcpy(air, sent, sizeof(air));
    rx.crypto.apply(air, sizeof(air), OTA_CRYPTO_DOWNLINK, rx.nonce);

    // OtaNonce wraps on the TX while the telemetry is on the air
    tx.tick();
    TEST_ASSERT_EQUAL_UINT8(0, tx.nonce);

    tx.crypto.apply(air, sizeof(air), OTA_CRYPTO_DOWNLINK, capturedEpoch, capturedNonce);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sent, air, sizeof(sent));
}

/***** Sync guard *****/

#define RATE_CURRENT 3
#define RATE_NEW 5
#define RATE_OTHER 7

// A corrupt packet passes the CRC and claims a wrong counter, nonce and rate on a working link.
// Without the guard, the RX would act on it and stop decoding.
void test_false_sync_does_not_break_a_healthy_link(void)
{
    SimTx tx;
    SimRx rx;
    OtaSyncGuard guard;
    connect(tx, rx);
    TEST_ASSERT_TRUE(slot(tx, rx));

    const uint8_t falseHigh = 0xde, falseLow = 0xad, falseNonce = rx.nonce + 77;
    const bool matches = rx.nonce == falseNonce && rx.crypto.syncMatches(falseHigh, falseLow, OTA_CRYPTO_SYNC_ROLLING);
    TEST_ASSERT_FALSE(matches);

    if (guard.allow(true, matches, RATE_OTHER))
    {
        rx.crypto.receiveSync(falseHigh, falseLow, OTA_CRYPTO_SYNC_ROLLING, rx.nonce, falseNonce);
        rx.nonce = falseNonce;
    }

    TEST_ASSERT_TRUE(slot(tx, rx));
}

// Packets stop arriving after a nonce slip, so the very next sync must be believed
void test_sync_is_believed_as_soon_as_the_link_is_unhealthy(void)
{
    OtaSyncGuard guard;
    TEST_ASSERT_TRUE(guard.allow(false, false, RATE_OTHER));
    // Nor does that one count towards confirming a sync on a healthy link later
    TEST_ASSERT_FALSE(guard.allow(true, false, RATE_OTHER));
}

void test_matching_sync_is_always_believed(void)
{
    OtaSyncGuard guard;
    for (unsigned i = 0; i < 10; ++i)
    {
        TEST_ASSERT_TRUE(guard.allow(true, true, RATE_CURRENT));
    }
}

// The TX asks for a rate change with several sync packets, while the link is still working
void test_rate_change_is_believed_on_the_second_sync(void)
{
    OtaSyncGuard guard;
    TEST_ASSERT_FALSE(guard.allow(true, false, RATE_NEW));
    TEST_ASSERT_TRUE(guard.allow(true, false, RATE_NEW));
    // Used up by that, so the next one starts again
    TEST_ASSERT_FALSE(guard.allow(true, false, RATE_NEW));
}

// Real syncs keep matching after a false one, which must not then confirm a later false one
void test_matching_sync_clears_a_waiting_false_sync(void)
{
    OtaSyncGuard guard;
    TEST_ASSERT_FALSE(guard.allow(true, false, RATE_OTHER));
    TEST_ASSERT_TRUE(guard.allow(true, true, RATE_CURRENT));
    TEST_ASSERT_FALSE(guard.allow(true, false, RATE_OTHER));
}

void test_different_rate_does_not_confirm(void)
{
    OtaSyncGuard guard;
    TEST_ASSERT_FALSE(guard.allow(true, false, RATE_OTHER));
    TEST_ASSERT_FALSE(guard.allow(true, false, RATE_NEW));
    TEST_ASSERT_TRUE(guard.allow(true, false, RATE_NEW));
}

void test_sync_matches_checks_the_field_it_carries(void)
{
    SimTx tx;
    SimRx rx;
    connect(tx, rx);
    tx.crypto.setBootCount(0x1234);
    rx.crypto.setBootCount(0x1234);
    for (unsigned i = 0; i < 256; ++i)
    {
        tx.tick();
        rx.tick();
    }

    uint8_t high, low;
    OtaCryptoSyncField_e field;
    for (unsigned i = 0; i < 2; ++i)
    {
        tx.crypto.fillSync(&high, &low, &field);
        TEST_ASSERT_TRUE(rx.crypto.syncMatches(high, low, field));
        TEST_ASSERT_FALSE(rx.crypto.syncMatches(high ^ 0x01, low, field));
        TEST_ASSERT_FALSE(rx.crypto.syncMatches(high, low ^ 0x01, field));
        // The same bytes under the other field are a different value, as rolling != bootCount here
        const OtaCryptoSyncField_e other = (field == OTA_CRYPTO_SYNC_ROLLING) ? OTA_CRYPTO_SYNC_BOOTCOUNT : OTA_CRYPTO_SYNC_ROLLING;
        TEST_ASSERT_FALSE(rx.crypto.syncMatches(high, low, other));
    }
}

int main(int argc, char **argv)
{
    UNITY_BEGIN();
    RUN_TEST(test_chacha20_known_answer);
    RUN_TEST(test_roundtrip_std_and_full_size);
    RUN_TEST(test_packet_type_stays_readable);
    RUN_TEST(test_unencrypted_packet_is_rejected);
    RUN_TEST(test_wrong_key_is_rejected);
    RUN_TEST(test_any_burst_of_loss_recovers_immediately);
    RUN_TEST(test_random_loss_never_causes_a_decode_failure);
    RUN_TEST(test_rx_reboot_recovers_from_two_syncs);
    RUN_TEST(test_tx_reboot_recovers_from_two_syncs);
    RUN_TEST(test_rx_with_stopped_timer_recovers_from_sync);
    RUN_TEST(test_rate_change_recovers_from_first_sync);
    RUN_TEST(test_bootcount_only_sync_follows_small_nonce_slip_across_wrap);
    RUN_TEST(test_rolling_wrap_stays_in_step);
    RUN_TEST(test_every_counter_field_changes_the_keystream);
    RUN_TEST(test_tx_never_reuses_a_counter);
    RUN_TEST(test_uplink_and_telemetry_never_share_keystream);
    RUN_TEST(test_sync_alternates_between_rolling_and_bootcount);
    RUN_TEST(test_telemetry_decodes_with_captured_epoch_across_wrap);
    RUN_TEST(test_false_sync_does_not_break_a_healthy_link);
    RUN_TEST(test_sync_is_believed_as_soon_as_the_link_is_unhealthy);
    RUN_TEST(test_matching_sync_is_always_believed);
    RUN_TEST(test_rate_change_is_believed_on_the_second_sync);
    RUN_TEST(test_matching_sync_clears_a_waiting_false_sync);
    RUN_TEST(test_different_rate_does_not_confirm);
    RUN_TEST(test_sync_matches_checks_the_field_it_carries);
    return UNITY_END();
}
