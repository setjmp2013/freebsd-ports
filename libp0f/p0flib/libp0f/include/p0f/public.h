#ifndef _P0F_PUBLIC_H
#define _P0F_PUBLIC_H

#include <p0f/config-p0f.h>

/**********************************
 **
 **  types.h 
 **
 **********************************/

typedef unsigned char		_u8;
typedef unsigned short		_u16;
typedef unsigned int		_u32;

#ifdef WIN32
typedef unsigned __int64	_u64;
#else
typedef unsigned long long	_u64;
#endif /* ^WIN32 */

typedef signed char		_s8;
typedef signed short		_s16;
typedef signed int		_s32;

#ifdef WIN32
typedef signed __int64	_s64;
#else
typedef signed long long	_s64;
#endif /* ^WIN32 */

/**********************************
 **
 **  fpentry.h 
 **
 **********************************/

#define MOD_NONE	0
#define MOD_CONST	1
#define MOD_MSS		2
#define MOD_MTU		3

typedef enum Quirks
{
  QUIRK_PAST         = 0x00000001, /*!< P - Options past EOL */
  QUIRK_ZEROID       = 0x00000002, /*!< Z - Zero IP ID */
  QUIRK_IPOPT        = 0x00000004, /*!< I - IP options specified */
  QUIRK_URG          = 0x00000008, /*!< U - URG pointer non-zero */
  QUIRK_X2           = 0x00000010, /*!< X - Unused (x2) field non-zero */
  QUIRK_ACK          = 0x00000020, /*!< A - ACK number non-zero */
  QUIRK_T2           = 0x00000040, /*!< T - Non-zero second timestamp */
  QUIRK_FLAGS        = 0x00000080, /*!< F - Unusual flags (PUSH, URG, etc) */
  QUIRK_DATA         = 0x00000100, /*!< D - Data payload */
  QUIRK_BROKEN       = 0x00000200, /*!< ! - Broken options segment */
  QUIRK_RSTACK       = 0x00000400, /*!< K - QUIRK_RSTACK (Only valid in RST+ mode) */
  QUIRK_SEQEQ        = 0x00000800, /*!< Q - QUIRK_SEQEQ (Only valid in RST+ mode) */
  QUIRK_SEQ0         = 0x00001000, /*!< 0 - QUIRK_SEQ0 (Only valid in RST+ mode) */
  QUIRK_EOL          = 0x00008000  /*!< E - EOL (deprecated, append EOL to Options) */
} eQuirks;

typedef enum FingerprintTypes
{
  FPTYPE_SYN          = (1<<0),  /*!< SYN */
  FPTYPE_SYNACK       = (1<<1),  /*!< SYN+ACK */
  FPTYPE_STRAYACK     = (1<<2),  /*!< Stray ACK */
  FPTYPE_RST          = (1<<3),  /*!< RST/RST+ACK */
  FPTYPE_FIN          = (1<<4),  /*!< FIN packets (currently no methodology to use this data( */
} eFingerprintTypes;

struct fp_entry {
  _u8* os;		/* OS genre */
  _u8* desc;		/* OS description */
  _u8  no_detail;	/* Disable guesstimates */
  _u8  generic;		/* Generic hit */
  _u8  userland;	/* Userland stack */
  _u16 wsize;		/* window size */
  _u8  wsize_mod;	/* MOD_* for wsize */
  _u8  ttl,df;		/* TTL and don't fragment bit */
  _u8  zero_stamp;	/* timestamp option but zero value? */
  _u16 size;		/* packet size */
  _u8  optcnt;		/* option count */
  _u8  opt[MAXOPT];	/* TCPOPT_* */
  _u16 wsc,mss;		/* value for WSCALE and MSS options */
  _u8  wsc_mod,mss_mod;	/* modulo for WSCALE and MSS (NONE or CONST) */
  _u32 quirks;		/* packet quirks and bugs */
  _u32 line;		/* config file line */
  struct fp_entry* next;
};

typedef struct fingerprint_st {
  _u16 ip_total_len;              /* (tot)    Total length of IP packet (0 for FPTYPE_STRAYACK) */
  _u8  ip_do_not_fragment;        /* (df)     Don't Fragment Flag (1 bit) */
  _u8  ip_ttl;                    /* (ttl)    TTL value from IPv4 packet */
  _u16 tcp_window_size;           /* (wss)    TCP Receive windows for TCP */
  _u8  tcp_num_options;           /* (optcnt) Number of TCP options in following array */
  _u8  tcp_options[MAXOPT];       /* (opt)    List of TCP options in order */
  _u16 tcp_opt_max_segment_size;  /* (mss)    Maximum Segment Size from MSS TCP option */
  _u8  tcp_opt_window_scaling;    /* (wsc)    Window Scaling value from WSCALE TCP option */
  _u32 tcp_opt_timestamp;         /* (tstamp) Timestamp option from timestamp TCP option */
  _u32 quirks;                    /* (quirks) Bit field of TCP/IP quirks (see enum Quirks) */
  eFingerprintTypes fptype;       /*          Type of fingerprint */

  /* these fields are not needed for fingerprinting, including for displaying additional info in p0f */
  const struct tcp_header *tcph;
  const _u8 *  tcp_pay;
} fingerprint_t;

#ifdef IGNORE_ZEROID
#  undef QUIRK_ZEROID
#  define QUIRK_ZEROID	0
#endif /* IGNORE_ZEROID */



/**********************************
 **
 **  p0f-lookup.h 
 **
 **********************************/

struct fp_database
{
  _u8         ack_mode;      /* load_config, main */
  _u8         rst_mode;      /* load_config, parse, main */
  _u8         open_mode;     /* load_config, display_signature, lookup_match, parse, main */

  _u32 sigcnt; /* load_config, main */
  _u32 gencnt; /* load_config, main */

  _u32 file_cksum;

  struct fp_entry sig[MAXSIGS]; /* collide, load_config, find_match */

/* By hash */
  struct fp_entry* bh[16]; /* load_config, lookup_match */
};

int parse   (fingerprint_t * return_struct, const _u8* packet, _u16 length, _u32 valid_modes);


const struct fp_entry* lookup_match(const struct fp_database* fp_db, _u16 tot,_u8 df,_u8 ttl,_u16 wss,
                                    _u8 ocnt, const _u8* op,_u16 mss, _u8 wsc,_u32 tstamp,_u8 tos,_u32 quirks, 
                                    _u8 use_fuzzy, _u8* nat, _u8* dfout );

void load_config(struct fp_database* db, _u8* file, _u8 check_collide);


#endif
