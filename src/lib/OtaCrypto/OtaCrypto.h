#pragma once

#include <cstddef>
#include <cstdint>

#include "ChaCha.h"

/**
 * Stateless over-the-air packet encryption.
 *
 * The keystream for a packet depends only on values that both ends can recover
 * from sync packets, never on which earlier packets arrived:
 *
 *   ChaCha20 64-bit block counter = [direction:8][bootCount:16][rolling:16][OtaNonce:8]
 *
 * - OtaNonce advances once per time slot on both ends, whether or not a packet
 *   arrived, and is corrected by every sync packet.
 * - rolling extends OtaNonce. It advances on each nonce wrap and each nonce reset.
 * - bootCount is saved in TX flash and advances on every TX boot, so a reboot
 *   can never reuse keystream.
 *
 * Losing any number of packets therefore costs exactly those packets. There is no
 * key exchange, so neither end can be left waiting for one after a reboot.
 *
 * Sync packets are sent unencrypted, and the two packet type bits of every packet
 * stay unencrypted, so the RX can always tell what it received.
 */

#define OTA_CRYPTO_KEY_SIZE 32

enum OtaCryptoDirection_e : uint8_t
{
    OTA_CRYPTO_UPLINK = 0,   // TX module to RX
    OTA_CRYPTO_DOWNLINK = 1, // RX to TX module
};

// Which half of the counter a sync packet is carrying
enum OtaCryptoSyncField_e : uint8_t
{
    OTA_CRYPTO_SYNC_ROLLING = 0,
    OTA_CRYPTO_SYNC_BOOTCOUNT = 1,
};

typedef struct
{
    uint16_t bootCount;
    uint16_t rolling;
} OtaCryptoEpoch_t;

class OtaCryptoSession
{
public:
    OtaCryptoSession();

    void init(const uint8_t key[OTA_CRYPTO_KEY_SIZE]);

    // Encrypts or decrypts a packet in place using the current epoch
    void apply(uint8_t *packet, size_t len, OtaCryptoDirection_e direction, uint8_t nonce);
    // As above, using an epoch captured earlier (the TX does this for telemetry)
    void apply(uint8_t *packet, size_t len, OtaCryptoDirection_e direction, OtaCryptoEpoch_t epoch, uint8_t nonce);

    OtaCryptoEpoch_t getEpoch() const { return {bootCount, rolling}; }

    // Both ends: call when OtaNonce wraps from 255 to 0
    void onNonceWrapped();

    // TX: call when OtaNonce is reset, as otherwise the same nonce values are used again
    void onNonceReset();
    // TX: at boot, before transmitting
    void setBootCount(uint16_t newBootCount);
    // TX: writes the fields a sync packet carries. Alternates between rolling and bootCount
    void fillSync(uint8_t *high, uint8_t *low, OtaCryptoSyncField_e *field);
    // TX: true once after rolling wraps into bootCount, so the new value can be saved
    bool takeBootCountChanged();

    // RX: call for every valid sync packet, before OtaNonce is updated from it
    void receiveSync(uint8_t high, uint8_t low, OtaCryptoSyncField_e field, uint8_t currentNonce, uint8_t syncNonce);
    // RX: true if a sync packet carries the value this end already has
    bool syncMatches(uint8_t high, uint8_t low, OtaCryptoSyncField_e field) const;

private:
    ChaCha cipher;
    volatile uint16_t bootCount;
    volatile uint16_t rolling;
    OtaCryptoSyncField_e nextSyncField;
    volatile bool bootCountChanged;
};

/**
 * Decides whether the RX should act on a sync packet.
 *
 * Sync packets have only the CRC and one UID bit to reject bad data, as the counter uses the
 * bytes that stock fills with the UID. About 1 in 131072 random packets gets through, and acting
 * on one could change the counter, nonce or packet rate of a working link.
 *
 * Valid packets still arriving prove the nonce and counter are right, so while that's true a
 * sync that disagrees with them is only believed once a second one asks for the same packet rate.
 * As soon as packets stop arriving, every sync is believed, so recovery is as fast as without this.
 */
class OtaSyncGuard
{
public:
    // linkHealthy: connected, with packets other than sync decoding recently
    // syncMatchesState: the nonce, FHSS index, packet rate and counter all match this end's
    // Returns true if the sync should be acted on
    bool allow(bool linkHealthy, bool syncMatchesState, uint8_t rateIndex);

private:
    bool waitingForConfirm = false;
    uint8_t rateToConfirm = 0;
};

extern OtaCryptoSession OtaCrypto;
