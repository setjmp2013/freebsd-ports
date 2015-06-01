#ifndef _P0F_PRIVATE_H
#define _P0F_PRIVATE_H

#include "p0f/config.h"

#define SIGHASH(tsize,optcnt,q,df) \
	(( (_u8) (((tsize) << 1) ^ ((optcnt) << 1) ^ (df) ^ (q) )) & 0x0f)

#ifdef WIN32

static inline void debug(_u8* format, ...) {
  _u8 buff[1024];
  va_list args;
  va_start(args, format);
  memset(buff, 0, sizeof(buff));
  _vsnprintf( buff, sizeof(buff) - 1, format, args);
  fprintf(stderr, buff);
  va_end(args);
}

static inline void fatal(_u8* format, ...) {
  _u8 buff[1024];
  va_list args;	
  va_start(args, format);
  memset(buff, 0, sizeof(buff));
  vsnprintf( buff, sizeof(buff) - 1, format, args);
  fprintf(stderr, "[-] ERROR: %s", buff);
  va_end(args);
  exit(1);
}

#else
#  define debug(x...)	fprintf(stderr,x)
#  define fatal(x...)	do { debug("[-] ERROR: " x); exit(1); } while (0)
#endif /* ^WIN32 */


#ifdef WIN32

static inline void debug(_u8* format, ...) {
  _u8 buff[1024];
  va_list args;
  va_start(args, format);
  memset(buff, 0, sizeof(buff));
  _vsnprintf( buff, sizeof(buff) - 1, format, args);
  fprintf(stderr, buff);
  va_end(args);
}

static inline void fatal(_u8* format, ...) {
  _u8 buff[1024];
  va_list args;	
  va_start(args, format);
  memset(buff, 0, sizeof(buff));
  vsnprintf( buff, sizeof(buff) - 1, format, args);
  fprintf(stderr, "[-] ERROR: %s", buff);
  va_end(args);
  exit(1);
}

#else
#  define debug(x...)	fprintf(stderr,x)
#  define fatal(x...)	do { debug("[-] ERROR: " x); exit(1); } while (0)
#endif /* ^WIN32 */

#define pfatal(x)	do { debug("[-] ERROR: "); perror(x); exit(1); } while (0)


#endif
