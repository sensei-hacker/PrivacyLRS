#include "OtaCrypto.h"

#include "targets.h"

// The low two bits of the first byte are the packet type (see OTA_Packet4_s and OTA_Packet8_s)
#define OTA_CRYPTO_TYPE_MASK 0b11

// The key is unique to the binding phrase and the counter never repeats under it, so
// the IV can be fixed. It only separates this use of the key from any future one.
static const uint8_t OTA_CRYPTO_IV[8] = {'P', 'r', 'i', 'v', 'L', 'R', 'S', '2'};

OtaCryptoSession OtaCrypto;

OtaCryptoSession::OtaCryptoSession()
    : cipher(20), bootCount(0), rolling(0), nextSyncField(OTA_CRYPTO_SYNC_ROLLING), bootCountChanged(false)
{
}

void OtaCryptoSession::init(const uint8_t key[OTA_CRYPTO_KEY_SIZE])
{
    cipher.setKey(key, OTA_CRYPTO_KEY_SIZE);
    cipher.setIV(OTA_CRYPTO_IV, sizeof(OTA_CRYPTO_IV));
}

void ICACHE_RAM_ATTR OtaCryptoSession::apply(uint8_t *packet, size_t len, OtaCryptoDirection_e direction, OtaCryptoEpoch_t atEpoch, uint8_t nonce)
{
    const uint8_t counter[8] = {
        nonce,
        (uint8_t)atEpoch.rolling,
        (uint8_t)(atEpoch.rolling >> 8),
        (uint8_t)atEpoch.bootCount,
        (uint8_t)(atEpoch.bootCount >> 8),
        (uint8_t)direction,
        0,
        0,
    };
    cipher.setCounter(counter, sizeof(counter));

    const uint8_t type = packet[0] & OTA_CRYPTO_TYPE_MASK;
    cipher.encrypt(packet, packet, len);
    packet[0] = (packet[0] & ~OTA_CRYPTO_TYPE_MASK) | type;
}

void ICACHE_RAM_ATTR OtaCryptoSession::apply(uint8_t *packet, size_t len, OtaCryptoDirection_e direction, uint8_t nonce)
{
    apply(packet, len, direction, getEpoch(), nonce);
}

void ICACHE_RAM_ATTR OtaCryptoSession::onNonceWrapped()
{
    rolling = rolling + 1;
    if (rolling == 0)
    {
        bootCount = bootCount + 1;
        bootCountChanged = true;
    }
}

void ICACHE_RAM_ATTR OtaCryptoSession::onNonceReset()
{
    onNonceWrapped();
    // The RX needs the new value first after the TX changes rate
    nextSyncField = OTA_CRYPTO_SYNC_ROLLING;
}

void OtaCryptoSession::setBootCount(uint16_t newBootCount)
{
    bootCount = newBootCount;
    rolling = 0;
}

void ICACHE_RAM_ATTR OtaCryptoSession::fillSync(uint8_t *high, uint8_t *low, OtaCryptoSyncField_e *field)
{
    const uint16_t value = (nextSyncField == OTA_CRYPTO_SYNC_ROLLING) ? rolling : bootCount;
    *high = value >> 8;
    *low = value;
    *field = nextSyncField;
    nextSyncField = (nextSyncField == OTA_CRYPTO_SYNC_ROLLING) ? OTA_CRYPTO_SYNC_BOOTCOUNT : OTA_CRYPTO_SYNC_ROLLING;
}

bool OtaCryptoSession::takeBootCountChanged()
{
    const bool changed = bootCountChanged;
    bootCountChanged = false;
    return changed;
}

void ICACHE_RAM_ATTR OtaCryptoSession::receiveSync(uint8_t high, uint8_t low, OtaCryptoSyncField_e field, uint8_t currentNonce, uint8_t syncNonce)
{
    const uint16_t value = ((uint16_t)high << 8) | low;
    if (field == OTA_CRYPTO_SYNC_ROLLING)
    {
        // Sent together with syncNonce, so this is exact
        rolling = value;
        return;
    }

    bootCount = value;

    // This sync has no rolling value but may still move OtaNonce across a wrap, for
    // example after a small slip. Follow the shortest path so the link stays decodable
    // until the next rolling value, which can be seconds away while connected.
    if (currentNonce > syncNonce && currentNonce - syncNonce > 128)
    {
        rolling = rolling + 1;
    }
    else if (syncNonce > currentNonce && syncNonce - currentNonce > 128)
    {
        rolling = rolling - 1;
    }
}

bool ICACHE_RAM_ATTR OtaCryptoSession::syncMatches(uint8_t high, uint8_t low, OtaCryptoSyncField_e field) const
{
    const uint16_t value = ((uint16_t)high << 8) | low;
    return value == ((field == OTA_CRYPTO_SYNC_ROLLING) ? rolling : bootCount);
}

bool ICACHE_RAM_ATTR OtaSyncGuard::allow(bool linkHealthy, bool syncMatchesState, uint8_t rateIndex)
{
    if (!linkHealthy || syncMatchesState)
    {
        waitingForConfirm = false;
        return true;
    }

    if (waitingForConfirm && rateToConfirm == rateIndex)
    {
        waitingForConfirm = false;
        return true;
    }

    waitingForConfirm = true;
    rateToConfirm = rateIndex;
    return false;
}
