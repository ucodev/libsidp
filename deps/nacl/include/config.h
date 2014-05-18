#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

#ifdef COMPILE_WIN32
#  if BUILDING_DLL
#    define DLLIMPORT __declspec (dllexport)
#  else /* Not BUILDING_DLL */
#    define DLLIMPORT __declspec (dllimport)
#  endif /* Not BUILDING_DLL */
#endif

#endif
