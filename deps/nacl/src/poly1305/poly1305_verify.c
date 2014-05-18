#include "config.h"
#include "crypto_onetimeauth.h"

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int crypto_onetimeauth_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[16];
  crypto_onetimeauth(correct,in,inlen,k);
  return crypto_verify_16(h,correct);
}
