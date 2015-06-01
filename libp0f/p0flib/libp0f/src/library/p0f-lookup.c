#include "p0f/public.h"
#include "p0f/tos.h"
#include "p0f/private.h"
#include "p0f/tcp.h"

#include <stdio.h>

//extern struct fp_entry* bh[16]; /* load_config, lookup_match */
//extern _u8    open_mode;     /* load_config, display_signature, lookup_match, parse, main */
//extern _u8    use_fuzzy;     /* lookup_match, main */


static _u8* lookup_tos(_u8 t) {
  _u32 i;

  if (!t) return 0;

  for (i=0;i<TOS_CNT;i++) {
   if (t == tos[i].tos) return tos[i].desc;
   if (t < tos[i].tos) break;
  }

  return 0;

}

static inline void display_signature( const struct fp_database* fp_db, _u8 ttl,_u16 tot,_u8 df,_u8* op,_u8 ocnt,
                                     _u16 mss,_u16 wss,_u8 wsc,_u32 tstamp,
                                     _u32 quirks) {

  _u32 j;
  _u8 d=0;

  if (mss && wss && !(wss % mss)) printf("S%d",wss/mss); else
  if (wss && !(wss % 1460)) printf("S%d",wss/1460); else
  if (mss && wss && !(wss % (mss+40))) printf("T%d",wss/(mss+40)); else
  if (wss && !(wss % 1500)) printf("T%d",wss/1500); else
  if (wss == 12345) printf("*(12345)"); else printf("%d",wss);

  if (!fp_db->open_mode) {
    if (tot < PACKET_BIG) printf(":%d:%d:%d:",ttl,df,tot);
    else printf(":%d:%d:*(%d):",ttl,df,tot);
  } else printf(":%d:%d:*:",ttl,df);
  
  for (j=0;j<ocnt;j++) {
    switch (op[j]) {
      case TCPOPT_NOP: putchar('N'); d=1; break;
      case TCPOPT_WSCALE: printf("W%d",wsc); d=1; break;
      case TCPOPT_MAXSEG: printf("M%d",mss); d=1; break;
      case TCPOPT_TIMESTAMP: putchar('T'); 
        if (!tstamp) putchar('0'); d=1; break;
      case TCPOPT_SACKOK: putchar('S'); d=1; break;
      case TCPOPT_EOL: putchar('E'); d=1; break;
      default: printf("?%d",op[j]); d=1; break;
    }
    if (j != ocnt-1) putchar(',');
  }

  if (!d) putchar('.');

  putchar(':');

  if (!quirks) putchar('.'); else {
    if (quirks & QUIRK_RSTACK) putchar('K');
    if (quirks & QUIRK_SEQEQ) putchar('Q');
    if (quirks & QUIRK_SEQ0) putchar('0');
    if (quirks & QUIRK_PAST) putchar('P');
    if (quirks & QUIRK_ZEROID) putchar('Z');
    if (quirks & QUIRK_IPOPT) putchar('I');
    if (quirks & QUIRK_URG) putchar('U');
    if (quirks & QUIRK_X2) putchar('X');
    if (quirks & QUIRK_ACK) putchar('A');
    if (quirks & QUIRK_T2) putchar('T');
    if (quirks & QUIRK_FLAGS) putchar('F');
    if (quirks & QUIRK_DATA) putchar('D');
    if (quirks & QUIRK_BROKEN) putchar('!');
  }

}



_u32 matched_packets;  /* lookup_match */

const struct fp_entry* lookup_match(const struct fp_database* fp_db, _u16 tot,_u8 df,_u8 ttl,_u16 wss,
                                    _u8 ocnt, const _u8* op,_u16 mss, _u8 wsc,_u32 tstamp,_u8 tos,_u32 quirks, 
                                    _u8 use_fuzzy, _u8* nat, _u8* dfout ) {

  _u32 j;
//  _u8  nat=0;
  struct fp_entry* p;
  _u8  orig_df  = df;
  _u8* tos_desc = 0;

  struct fp_entry* fuzzy = 0;
  _u8 fuzzy_now = 0;
  int i;

  *nat = 0;

  if( ocnt > MAXOPT )
  {
    printf( "lookup_match():  Option count exceeds MAXOPT (%d>%d)\n", ocnt, MAXOPT );
  }

  /*
  printf( "lookup_match: tot  = %d\n"
          "            df     = %d\n"
          "            ttl    = %d\n"
          "            wss    = %d\n"
          "            ocnt   = %d\n"
          , tot, df, ttl, wss, ocnt );
  printf( "            op     = [" );
  for( i=0; i<ocnt; i++ )
  {
    printf( "%d", op[i] );
    if( i+1 < ocnt )
      printf( ", " );
  }
  printf( "]\n" );
  printf( "            mss    = %d\n"
          "            wsc    = %d\n"
          "            tstamp = %u\n"
          "            tos    = %d\n"
          "            quirks = %d\n"
					, mss, wsc, tstamp, tos, quirks);

    printf("----- ");
display_signature( fp_db, ttl, tot, df,op, ocnt,
                                     mss, wss, wsc, tstamp,
                                    quirks);
    printf(" -----\n");
  */

re_lookup:

  p = fp_db->bh[SIGHASH(tot,ocnt,quirks,df)];

  if (tos) tos_desc = lookup_tos(tos);

  while (p) {
    /*
    display_signature( fp_db, p->ttl, p->size, p->df,p->opt, p->optcnt,
                                     p->mss, p->wsize, p->wsc, p->zero_stamp,
                                     p->quirks);
    printf("\n");
    */
  

    /* Cheap and specific checks first... */

    /* psize set to zero means >= PACKET_BIG */
    if (!fp_db->open_mode) {
      if (p->size) { if (tot ^ p->size) { p = p->next; continue; } }
        else if (tot < PACKET_BIG) { p = p->next; continue; }
    }

    if (ocnt ^ p->optcnt) { p = p->next; continue; }

    if (p->zero_stamp ^ (!tstamp)) { p = p->next; continue; }
    if (p->df ^ df) { p = p->next; continue; }
    if (p->quirks ^ quirks) { p = p->next; continue; }

    /* Check MSS and WSCALE... */
    if (!p->mss_mod) {
      if (mss ^ p->mss) { p = p->next; continue; }
    } else if (mss % p->mss) { p = p->next; continue; }

    if (!p->wsc_mod) {
      if (wsc ^ p->wsc) { p = p->next; continue; }
    } else if (wsc % p->wsc) { p = p->next; continue; }

    /* Then proceed with the most complex WSS check... */
    switch (p->wsize_mod) {
      case 0:
        if (wss ^ p->wsize) { p = p->next; continue; }
        break;
      case MOD_CONST:
        if (wss % p->wsize) { p = p->next; continue; }
        break;
      case MOD_MSS:
        if (mss && !(wss % mss)) {
          if ((wss / mss) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1460)) {
          if ((wss / 1460) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
      case MOD_MTU:
        if (mss && !(wss % (mss+40))) {
          if ((wss / (mss+40)) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1500)) {
          if ((wss / 1500) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
     }

    /* Numbers agree. Let's check options */

    for (j=0;j<ocnt;j++)
      if (p->opt[j] ^ op[j]) goto continue_search;

    /* Check TTLs last because we might want to go fuzzy. */
    if (p->ttl < ttl) {
      if (use_fuzzy) fuzzy = p;
      p = p->next;
      continue;
    }

    /* Naah... can't happen ;-) */
    if (!p->no_detail)
      if (p->ttl - ttl > MAXDIST) { 
        if (use_fuzzy) fuzzy = p;
        p = p->next; 
        continue; 
      }

continue_fuzzy:    
    
    /* Match! */
    
    matched_packets++;

    if (mss & wss) {
      if (p->wsize_mod == MOD_MSS) {
        if ((wss % mss) && !(wss % 1460)) *nat=1;
      } else if (p->wsize_mod == MOD_MTU) {
        if ((wss % (mss+40)) && !(wss % 1500)) *nat=2;
      }
    }

    *dfout = df;
    /*printf("osname=%s osver=%s\n", p->os, p->desc);*/
    return p;

continue_search:

    p = p->next;

  }

  if (!df) { df = 1; goto re_lookup; }

  if (use_fuzzy && fuzzy) {
    df = orig_df;
    fuzzy_now = 1;
    p = fuzzy;
    fuzzy = 0;
    goto continue_fuzzy;
  }

  *dfout = df;
  return NULL;
}
