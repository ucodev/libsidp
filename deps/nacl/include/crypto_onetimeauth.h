#ifndef CRYPTO_ONETIMEAUTH_POLY1305_H
#define CRYPTO_ONETIMEAUTH_POLY1305_H

#define crypto_onetimeauth_BYTES 16
#define crypto_onetimeauth_KEYBYTES 32

/* Prototypes */
int crypto_onetimeauth(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k);
int crypto_onetimeauth_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k);
int crypto_verify_16(const unsigned char *x,const unsigned char *y);

#endif
