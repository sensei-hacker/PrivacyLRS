"""Derives the UID and encryption key from a binding phrase.

Used by both build_flags.py and binary_configurator.py, because firmware built one way must
link to firmware configured the other way.
"""
import hashlib

# Slow on purpose: makes each guess at a binding phrase expensive.
# TX and RX must derive the same values, so the salt is fixed and not random per device.
KDF_SALT = b"PrivacyLRS-binding-phrase-v2"
KDF_ITERATIONS = 1000000
UID_SIZE = 6
KEY_SIZE = 32

_derived = {}

def derive_from_phrase(phrase):
    """Returns (uid, master_key) as bytes.

    The UID comes from the same slow derivation as the key. It goes over the air, in the FHSS
    sequence and the CRC seed, so a UID that was a fast hash of the phrase would let someone
    test guesses at the phrase cheaply and skip the slow step altogether.
    """
    if phrase not in _derived:
        derived = hashlib.pbkdf2_hmac('sha256', phrase.encode('utf-8'), KDF_SALT, KDF_ITERATIONS, dklen=KEY_SIZE + UID_SIZE)
        _derived[phrase] = (derived[KEY_SIZE:], derived[:KEY_SIZE])
    return _derived[phrase]
