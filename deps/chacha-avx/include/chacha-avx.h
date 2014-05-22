/* Chacha implementation for 16-byte vectors by Ted Krovetz (ted@krovetz.net).
 * Assumes 32-bit int, 64-bit long long. Public domain. Modified: 2013.06.19.
 * Chacha is an improvement on the stream cipher Salsa, described at
 * http://cr.yp.to/papers.html#chacha
 *
 * Original author repository: https://github.com/floodyberry/supercop/tree/master/crypto_stream/chacha20/krovetz/vec128
 *
 * Changes by Pedro A. Hortas (22/05/2013):
 *  - Changed function names. Added the prefix chacha_avx_*() to avoid conflicts with other NaCl library functions.
 *  - Added pre-processor conditions to avoid unused variables warnings.
 *
 */

#ifndef CRYPTO_CHACHA_AVX_H
#define CRYPTO_CHACHA_AVX_H

/* Properties */
#define CHACHA_AVX_CRYPTO_KEYBYTES	32
#define CHACHA_AVX_CRYPTO_NONCEBYTES	20

/* Prototypes */
int chacha_avx_crypto_stream_xor(unsigned char *out, const unsigned char *in, 
  unsigned long long inlen, const unsigned char *n, const unsigned char *k);
int chacha_avx_crypto_stream(unsigned char *out, unsigned long long outlen, 
  const unsigned char *n, const unsigned char *k);

#endif

