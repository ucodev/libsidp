#ifndef CRYPTO_STREAM_XSALSA20_H
#define CRYPTO_STREAM_XSALSA20_H

#define crypto_stream_KEYBYTES 32
#define crypto_stream_NONCEBYTES 24

/* Prototypes */
int crypto_stream_xor(
        unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
);
int crypto_core_hsalsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
);
int crypto_core_salsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
);
int crypto_stream_salsa20_xor(
        unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
);

#endif

