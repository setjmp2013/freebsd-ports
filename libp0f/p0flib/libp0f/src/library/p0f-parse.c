/*

   p0f - parsing interface
   ----------------------------

   Separates functionality to fingerprint a packet from the lookup and printing functionality

   Copyright (C) 2003-2006 by Michal Zalewski <lcamtuf@coredump.cx>

*/


#include <stdlib.h>
#include <sys/types.h>

#ifndef WIN32
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <pwd.h>
#  include <grp.h>
#else
//#  include "getopt.h"
//#  include <stdarg.h>
//#  pragma comment (lib, "wpcap.lib")
#endif /* ^WIN32 */

#include <stdio.h>

#include "p0f/private.h"
#include "p0f/public.h"
#include "p0f/tcp.h"

#define GET16(p) \
        ((_u16) *((_u8*)(p)+0) << 8 | \
         (_u16) *((_u8*)(p)+1) )


int parse(fingerprint_t * restrict return_struct, const _u8* restrict packet, _u16 length, _u32 valid_modes) {
  const  struct ip_header  * restrict iph = (struct ip_header *)packet;
  const  struct tcp_header * restrict tcph;
  struct timeval pts;
  const  _u8* restrict end_ptr = packet + (length > PACKET_SNAPLEN ? PACKET_SNAPLEN : length);
  const  _u8* restrict opt_ptr;
  _s32   ilen,olen;

  _u8    ocnt = 0;
//  _u16   mss_val = 0, wsc_val = 0;
  _u32   tstamp = 0;
  _u32   quirks = 0;

  eFingerprintTypes mode;

  /* Whoops, IP header ends past end_ptr */
  if ((_u8*)(iph + 1) > end_ptr) return 1;

  if ( ((iph->ihl & 0x40) != 0x40) || iph->proto != IPPROTO_TCP) {
    debug("[!] WARNING: Non-IP packet received. Bad header_len!\n");
    return 2;
  }

  /* If the declared length is shorter than the snapshot (etherleak
     or such), truncate this bad boy. */

  opt_ptr = (_u8*)iph + htons(iph->tot_len);
  if (end_ptr > opt_ptr) end_ptr = opt_ptr;

  ilen = iph->ihl & 15;

  /* Borken packet */
  if (ilen < 5) return 3;

  if (ilen > 5) {

#ifdef DEBUG_EXTRAS
    _u8 i;
    printf("  -- EXTRA IP OPTIONS (packet below): ");
    for (i=0;i<ilen-5;i++)
      printf("%08x ",(_u32)ntohl(*(((_u32*)(iph+1))+i)));
    putchar('\n');
    fflush(0);
#endif /* DEBUG_EXTRAS */

    quirks |= QUIRK_IPOPT;
  }

  return_struct->tcp_pay = 0;
  return_struct->tcph = tcph = (struct tcp_header*)((_u8*)iph + (ilen << 2));
  opt_ptr = (_u8*)(tcph + 1);

  mode = 0;
  if( (tcph)->flags & TH_SYN ) {
    if( tcph->flags & TH_ACK ) 
      mode = FPTYPE_SYNACK;
    else 
      mode = FPTYPE_SYN;
  } else if( tcph->flags & TH_ACK ) {
    mode = FPTYPE_STRAYACK;
  } else if( tcph->flags & TH_RST ) {
    mode = FPTYPE_RST;
  } else if( (tcph)->flags & TH_FIN ) {
    mode = FPTYPE_FIN;
  }

  if( !(mode & valid_modes) ) { return 8; } //no use generating a fingerprint for an unwanted packet

  /* Whoops, TCP header would end past end_ptr */
  if (opt_ptr > end_ptr) return 4;

  if (mode == FPTYPE_RST && (tcph->flags & TH_ACK)) quirks |= QUIRK_RSTACK;

  if (tcph->seq == tcph->ack) quirks |= QUIRK_SEQEQ;
  if (!tcph->seq) quirks |= QUIRK_SEQ0;

  if (tcph->flags & ~(TH_SYN|TH_ACK|TH_RST|TH_ECE|TH_CWR
                      | (mode==FPTYPE_STRAYACK ? TH_PUSH:0)
                      | (mode==FPTYPE_FIN ? TH_FIN:0)))
    quirks |= QUIRK_FLAGS;

  ilen=((tcph->doff) << 2) - sizeof(struct tcp_header);

  if ( (_u8*)opt_ptr + ilen < end_ptr) {

#ifdef DEBUG_EXTRAS
    _u32 i;

    printf("  -- EXTRA PAYLOAD (packet below): ");

    for (i=0;i< (_u32)end_ptr - ilen - (_u32)opt_ptr;i++)
      printf("%02x ",*(opt_ptr + ilen + i));

    putchar('\n');
    fflush(0);
#endif /* DEBUG_EXTRAS */

    if (mode != FPTYPE_STRAYACK) quirks |= QUIRK_DATA;
    return_struct->tcp_pay = opt_ptr + ilen;

  } 

  while (ilen > 0) {

    ilen--;

    switch (*(opt_ptr++)) {
      case TCPOPT_EOL:
        /* EOL */
        return_struct->tcp_options[ocnt] = TCPOPT_EOL;
        ocnt++;

        if (ilen) {

          quirks |= QUIRK_PAST;

#ifdef DEBUG_EXTRAS

          printf("  -- EXTRA TCP OPTIONS (packet below): ");

          while (ilen) {
            ilen--;
            if (opt_ptr >= end_ptr) { printf("..."); break; }
            printf("%02x ",*(opt_ptr++));
          }

          putchar('\n');
          fflush(0);

#endif /* DEBUG_EXTRAS */

        }

        /* This goto will be probably removed at some point. */
        goto end_parsing;

      case TCPOPT_NOP:
        /* NOP */
        return_struct->tcp_options[ocnt] = TCPOPT_NOP;
        ocnt++;
        break;

      case TCPOPT_SACKOK:
        /* SACKOK LEN */
        return_struct->tcp_options[ocnt] = TCPOPT_SACKOK;
        ocnt++; ilen--; opt_ptr++;
        break;

      case TCPOPT_MAXSEG:
        /* MSS LEN D0 D1 */
        if (opt_ptr + 3 > end_ptr) {
borken:
          quirks |= QUIRK_BROKEN;
          goto end_parsing;
        }
        return_struct->tcp_options[ocnt] = TCPOPT_MAXSEG;
        //mss_val = GET16(opt_ptr+1);
        return_struct->tcp_opt_max_segment_size = GET16(opt_ptr+1);
        ocnt++; ilen -= 3; opt_ptr += 3;
        break;

      case TCPOPT_WSCALE:
        /* WSCALE LEN D0 */
        if (opt_ptr + 2 > end_ptr) goto borken;
        return_struct->tcp_options[ocnt] = TCPOPT_WSCALE;
//        wsc_val = *(_u8 *)(opt_ptr + 1);
        return_struct->tcp_opt_window_scaling = *(_u8 *)(opt_ptr + 1);
        ocnt++; ilen -= 2; opt_ptr += 2;
        break;

      case TCPOPT_TIMESTAMP:
        /* TSTAMP LEN T0 T1 T2 T3 A0 A1 A2 A3 */
        if (opt_ptr + 9 > end_ptr) goto borken;
        return_struct->tcp_options[ocnt] = TCPOPT_TIMESTAMP;

        memcpy(&tstamp, opt_ptr+5, 4);
        if (tstamp) quirks |= QUIRK_T2;

        memcpy(&tstamp, opt_ptr+1, 4);
        return_struct->tcp_opt_timestamp = ntohl(tstamp);

        ocnt++; ilen -= 9; opt_ptr += 9;
        break;

      default:

        /* Hrmpf... */
        if (opt_ptr + 1 > end_ptr) goto borken;

        return_struct->tcp_options[ocnt] = *(opt_ptr-1);
        olen = *(_u8*)(opt_ptr)-1;
        if (olen > 32 || (olen < 0)) goto borken;

        ocnt++; ilen -= olen; opt_ptr += olen;
        break;

     }

     if (ocnt >= MAXOPT-1) goto borken;

     /* Whoops, we're past end_ptr */
     if (ilen > 0)
       if (opt_ptr >= end_ptr) goto borken;

   }

end_parsing:

   if (tcph->ack) quirks |= QUIRK_ACK;
   if (tcph->urg) quirks |= QUIRK_URG;
   if (tcph->_x2) quirks |= QUIRK_X2;
   if (!iph->id)  quirks |= QUIRK_ZEROID;

   return_struct->ip_total_len = (mode == FPTYPE_STRAYACK ? 0 : ntohs(iph->tot_len)); //0 if data is normal, IP length otherwise
   return_struct->ip_do_not_fragment = (ntohs(iph->off) & IP_DF) != 0;
   return_struct->ip_ttl = iph->ttl;
   return_struct->tcp_window_size = ntohs(tcph->win);
   return_struct->tcp_num_options = ocnt;
   return_struct->quirks = quirks;
   return_struct->fptype = mode;

#ifdef DEBUG_EXTRAS

  if (quirks & QUIRK_FLAGS || tcph->ack || tcph->_x2 || tcph->urg)
    printf("  -- EXTRA TCP VALUES: ACK=0x%x, UNUSED=%d, URG=0x%x "
           "(flags = %x)\n",tcph->ack,tcph->_x2,tcph->urg,tcph->flags);
  fflush(0);

#endif /* DEBUG_EXTRAS */
  return 0;
}

