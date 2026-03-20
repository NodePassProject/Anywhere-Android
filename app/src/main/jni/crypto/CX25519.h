/*
 * CX25519.h
 *
 * Portable X25519 Diffie-Hellman key exchange (RFC 7748).
 * Provides key pair generation and shared secret computation.
 */

#ifndef CX25519_H
#define CX25519_H

#include <stdint.h>

/**
 * Generate an X25519 key pair.
 *
 * @param public_key  Output: 32-byte public key.
 * @param private_key Output: 32-byte private key (clamped per RFC 7748).
 */
void x25519_generate_keypair(uint8_t public_key[32], uint8_t private_key[32]);

/**
 * Compute X25519 shared secret.
 *
 * @param shared_secret Output: 32-byte shared secret.
 * @param private_key   32-byte private key (clamped).
 * @param peer_public_key 32-byte peer's public key.
 * @return 0 on success, -1 if the result is the all-zero point (invalid).
 */
int x25519_key_agreement(uint8_t shared_secret[32],
                         const uint8_t private_key[32],
                         const uint8_t peer_public_key[32]);

#endif /* CX25519_H */
