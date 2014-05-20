/**
 * Original Author: Samuel Neves
 * Original GitHub Repository: https://github.com/sneves/chacha-avx2
 * Public Domain
 *
 * Changes by Pedro A. Hortas:
 *  - Added the CHACHA_AVX2_* prefix for consistency with other SIDP code.
 *  - Added the Prototypes section.
 *
 */

#ifndef CRYPTO_CHACHA_AVX2_H
#define CRYPTO_CHACHA_AVX2_H

/* Properties */
#define CHACHA_AVX2_CRYPTO_KEYBYTES	32
#define CHACHA_AVX2_CRYPTO_NONCEBYTES	8

/* Prototypes */
int chacha_avx2_crypto_stream_xor(unsigned char *out, const unsigned char *in, 
  unsigned long long inlen, const unsigned char *n_, const unsigned char *k_);
int chacha_avx2_crypto_stream(unsigned char *out, unsigned long long outlen, 
  const unsigned char *n, const unsigned char *k);

#endif
