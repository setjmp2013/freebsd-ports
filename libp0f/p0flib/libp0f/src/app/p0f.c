/*

  p0f - passive OS fingerprinting 
  -------------------------------

  "If you sit down at a poker game and don't see a sucker, 
  get up. You're the sucker."

  (C) Copyright 2000-2006 by Michal Zalewski <lcamtuf@coredump.cx>

  WIN32 port (C) Copyright 2003-2004 by Michael A. Davis <mike@datanerds.net>
             (C) Copyright 2003-2004 by Kirby Kuehl <kkuehl@cisco.com>

*/

#include <stdlib.h>
#include <string.h>
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
#  include "getopt.h"
#  include <stdarg.h>
#  pragma comment (lib, "wpcap.lib")
#endif /* ^WIN32 */

#include <stdio.h>
#include <pcap.h>
#include <signal.h>

#ifdef USE_BPF
#include USE_BPF
#else
#include <pcap-bpf.h>
#endif /* ^USE_BPF */

#include <time.h>
#include <ctype.h>

/* #define DEBUG_HASH - display signature hash table stats */

#include "p0f/public.h"
#include "p0f/config.h"
#include "p0f/tcp.h"
#include "p0f/mtu.h"
#include "p0f/tos.h"
#include "p0f/p0f-query.h"
#include "p0f/private.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif /* ! MSG_NOSIGNAL */

static pcap_dumper_t *dumper;  /* die_nicely, parse, main */

static struct fp_database fp_db;

/*static struct fp_entry sig[MAXSIGS];*/ /* collide, load_config, find_match */
/*static _u32 sigcnt;*/ /* load_config, main */
/*static _u32 gencnt;*/ /* load_config, main */

/* By hash */
/*static struct fp_entry* bh[16];*/ /* load_config, lookup_match */

static _u8 *config_file, /* main */
           *use_iface,   /* main */
           *use_dump,    /* main */
           *write_dump,  /* main */
           *use_cache,   /* die_nicely, find_match, main */
#ifndef WIN32
           *set_user,    /* main */
#endif /* !WIN32 */
           *use_rule = "tcp[13] & 0x17 == 2"; /* main */

static _u32 query_cache = DEFAULT_QUERY_CACHE; /* die_nicely, main */
static _s32 masq_thres; /* find_match, main */
static _s32 capture_timeout = 1; /* main */

static _u8 no_extra,      /* find_match, main */
           find_masq,     /* die_nicely, find_match, main */
           masq_flags,    /* find_match, main */
           no_osdesc,     /* find_match, main */
           no_known,      /* find_match, main */
           no_unknown,    /* find_match, main */
           no_banner,     /* die_nicely, find_match, main */
           use_promisc,   /* main */
           add_timestamp, /* put_date, find_match, main */
           header_len,    /* set_header_len, parse, main */
           /*ack_mode,*/      /* load_config, main */
           /*rst_mode,*/      /* load_config, parse, main */
           /*open_mode,*/     /* load_config, display_signature, lookup_match, parse, main */
           go_daemon,     /* main */
           use_logfile,   /* main */
           mode_oneline,  /* dump_payload, find_match, main */
           always_sig,    /* find_match, main */
           do_resolve,    /* grab_name, main */
           /*check_collide,*/ /* load_config, main */
           full_dump,     /* find_match, main */
           use_fuzzy,     /* lookup_match, main */
           use_vlan,      /* parse, main */
           payload_dump,  /* find_match, main */
           port0_wild;    /* main */
           

static pcap_t *pt;             /* die_nicely, main */
static struct bpf_program flt; /* main */

/* Exports for p0f statistics */
_u32 packet_count;        /* die_nicely, parse */
_u8  operating_mode;      /* main */
_u32 st_time;             /* die_nicely, main */
/*_u32 file_cksum;*/          /* load_config, main */


static void die_nicely(_s32 sig) {
  if (sig) debug("+++ Exiting on signal %d +++\n",sig);
  if (pt) pcap_close(pt);
  if (dumper) pcap_dump_close(dumper);

  if (!no_banner && packet_count) {
    float r = packet_count * 60;
    
    r /= (time(0) - st_time);

    debug("[+] Average packet ratio: %0.2f per minute",r);

    if (use_cache || find_masq)
      debug(" (cache: %0.2f seconds).\n",query_cache * 60 / r);
    else
    debug(".\n");
  }

  exit(sig);
}


static void set_header_len(_u32 type) {

  switch(type) {

    case DLT_SLIP:
    case DLT_RAW:  break;

#ifdef DLT_C_HDLC
    case DLT_C_HDLC:
#endif

    case DLT_NULL: header_len=4; break;

    case DLT_EN10MB: header_len=14; break;

#ifdef DLT_LOOP
    case DLT_LOOP:
#endif

#ifdef DLT_PPP_SERIAL
    case DLT_PPP_SERIAL: /* NetBSD oddity */
#endif

#ifdef DLT_PPP_ETHER
    case DLT_PPP_ETHER:  /* PPPoE on NetBSD */
        header_len=8;
        break;
#endif

    case DLT_PPP:    header_len=4; break;

    case DLT_IEEE802:
      header_len=22;
      break;

#ifdef DLT_IEEE802_11
    case DLT_IEEE802_11: header_len=32; break;
#endif

#ifdef DLT_PFLOG
    case DLT_PFLOG:
      header_len=28;
      break;
#endif

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
      header_len=16;
      break;
#endif

    default:
      debug("[!] WARNING: Unknown datalink type %d, assuming no header.\n",type);
      break;

  }

}



static void usage(_u8* name) {
  fprintf(stderr,
          "\nUsage: %s [ -f file ] [ -i device ] [ -s file ] [ -o file ]\n"

#ifndef WIN32
          "       [ -w file ] [ -Q sock [ -0 ] ] [ -u user ] [ -FXVNDUKASCMROqtpvdlrx ]\n"
          "       [ -c size ] [ -T nn ] [ -e nn ] [ 'filter rule' ]\n"
#else
		  "       [ -w file ] [ -FXVNDUKASCMLROqtpvdlrx ]\n"
		  "       [ -c size]  [ -T nn ] [ -e nn ] [ 'filter rule' ]\n"
#endif /* ^WIN32 */

          "  -f file   - read fingerprints from file\n"
          "  -i device - listen on this device\n"
          "  -s file   - read packets from tcpdump snapshot\n"
          "  -o file   - write to this logfile (implies -t)\n"
          "  -w file   - save packets to tcpdump snapshot\n"
#ifndef WIN32
          "  -u user   - chroot and setuid to this user\n"
          "  -Q sock   - listen on local socket for queries\n"
          "  -0        - make src port 0 a wildcard (in query mode)\n"
#endif /* !WIN32 */
          "  -e ms     - pcap capture timeout in milliseconds (default: 1)\n"
          "  -c size   - cache size for -Q and -M options\n"
          "  -M        - run masquerade detection\n"
          "  -T nn     - set masquerade detection threshold (1-200)\n"
          "  -V        - verbose masquerade flags reporting\n"
          "  -F        - use fuzzy matching (do not combine with -R)\n"
          "  -N        - do not report distances and link media\n"
          "  -D        - do not report OS details (just genre)\n"
          "  -U        - do not display unknown signatures\n"
          "  -K        - do not display known signatures (for tests)\n"
          "  -S        - report signatures even for known systems\n"
          "  -A        - go into SYN+ACK mode (semi-supported)\n"
          "  -R        - go into RST/RST+ACK mode (semi-supported)\n"
          "  -O        - go into stray ACK mode (barely supported)\n"
          "  -r        - resolve host names (not recommended)\n"
          "  -q        - be quiet - no banner\n"
          "  -v        - enable support for 802.1Q VLAN frames\n"
          "  -p        - switch card to promiscuous mode\n"
          "  -d        - daemon mode (fork into background)\n"
          "  -l        - use single-line output (easier to grep)\n"
          "  -x        - include full packet dump (for debugging)\n"
          "  -X        - display payload string (useful in RST mode)\n"
          "  -C        - run signature collision check\n"
#ifdef WIN32
          "  -L        - list all available interfaces\n"
#endif /* ^WIN32 */
          "  -t        - add timestamps to every entry\n\n"
          "  'Filter rule' is an optional pcap-style BPF expression (man tcpdump).\n\n",name);
  exit(1);
}






static _u8* lookup_link(_u16 mss,_u8 txt) {
  _u32 i;
  static _u8 tmp[32];

  if (!mss) return txt ? "unspecified" : 0;
  mss += 40;
  
  for (i=0;i<MTU_CNT;i++) {
   if (mss == mtu[i].mtu) return mtu[i].dev;
   if (mss < mtu[i].mtu)  goto unknown;
  }

unknown:

  if (!txt) return 0;
  sprintf(tmp,"unknown-%d",mss);
  return tmp;

}


static void put_date(struct timeval tval) {
  _u8* x;
  struct tm *tmval;

  switch (add_timestamp) {

    case 1: /* localtime */

    case 2: /* UTC */

      x = asctime((add_timestamp == 1) ? localtime(&tval.tv_sec) : 
                                         gmtime(&tval.tv_sec));

      if (x[strlen(x)-1]=='\n') x[strlen(x)-1]=0;

      printf("<%s> ",x);

      break;

    case 3: /* seconds since the epoch */

      printf("<%u.%06u> ", (_u32)tval.tv_sec, (_u32)tval.tv_usec);
      break;

    case 4: /* RFC3339 */
    default:

      tmval = gmtime(&tval.tv_sec);

      printf("<%04u-%02u-%02uT%02u:%02u:%02u.%06uZ> ",
             tmval->tm_year + 1900, tmval->tm_mon + 1, tmval->tm_mday,
             tmval->tm_hour, tmval->tm_min, tmval->tm_sec, 
             (_u32)tval.tv_usec);

      break;

  }

}


static inline _u8* grab_name(_u8* a) {
  struct hostent* r;
  static _u8 rbuf[MY_MAXDNS+6] = "/";
  _u32 j;
  _u8 *s,*d = rbuf+1;

  if (!do_resolve) return "";
  r = gethostbyaddr(a,4,AF_INET);
  if (!r || !(s = r->h_name) || !(j = strlen(s))) return "";
  if (j > MY_MAXDNS) return "";

  while (j--) {
    if (isalnum(*s) || *s == '-' || *s == '.') *d = *s;
      else *d = '?';
    d++; s++;
  }

  *d=0;

  return rbuf;

}


static inline void display_signature(_u8 ttl,_u16 tot,_u8 df,_u8* op,_u8 ocnt,
                                     _u16 mss,_u16 wss,_u8 wsc,_u32 tstamp,
                                     _u32 quirks) {

  _u32 j;
  _u8 d=0;

  if (mss && wss && !(wss % mss)) printf("S%d",wss/mss); else
  if (wss && !(wss % 1460)) printf("S%d",wss/1460); else
  if (mss && wss && !(wss % (mss+40))) printf("T%d",wss/(mss+40)); else
  if (wss && !(wss % 1500)) printf("T%d",wss/1500); else
  if (wss == 12345) printf("*(12345)"); else printf("%d",wss);

  if (!fp_db.open_mode) {
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


static void dump_packet(_u8* pkt,_u16 plen) {
  _u32 i;
  _u8  tbuf[PKT_DLEN+1];
  _u8* t = tbuf;
 
  for (i=0;i<plen;i++) {
    _u8 c = *(pkt++);
    if (!(i % PKT_DLEN)) printf("  [%02x] ",i);
    printf("%02x ",c);
    *(t++) = isprint(c) ? c : '.';
    if (!((i+1) % PKT_DLEN)) {
      *t=0;
      printf(" | %s\n",(t=tbuf));
    }
  }
  
  if (plen % PKT_DLEN) {
    *t=0;
    while (plen++ % PKT_DLEN) printf("   ");
    printf(" | %s\n",tbuf);
  }

}


static void dump_payload(const _u8* data,_u16 dlen) {
  _u8  tbuf[PKT_MAXPAY+2];
  _u8* t = tbuf;
  _u8  i;
  _u8  max = dlen > PKT_MAXPAY ? PKT_MAXPAY : dlen;

  if (!dlen) return;

  for (i=0;i<max;i++) {
    if (isprint(*data)) *(t++) = *data; 
      else if (!*data)  *(t++) = '?';
      else *(t++) = '.';
    data++;
  }

  *t = 0;

  if (!mode_oneline) putchar('\n');
  printf("  # Payload: \"%s\"%s",tbuf,dlen > PKT_MAXPAY ? "..." : "");

}

  

static inline void find_match(_u16 tot,_u8 df,_u8 ttl,_u16 wss,_u32 src,
                       _u32 dst,_u16 sp,_u16 dp,_u8 ocnt,_u8* op,_u16 mss,
                       _u8 wsc,_u32 tstamp,_u8 tos,_u32 quirks,_u8 ecn,
                       _u8* pkt,_u8 plen,const _u8* pay, struct timeval pts) {

  _u8* a;
  _u8  nat=0;  // Need to get from lookup_match
  const struct fp_entry* p;
  _u8  orig_df  = df;  // Need to get modified df from lookup_match
  _u8  dfout;
  _u8* tos_desc = 0;

  _u8 fuzzy_now = 0;

  p = lookup_match( &fp_db, tot, df, ttl, wss, ocnt, op, mss,
                    wsc, tstamp, tos, quirks, use_fuzzy, &nat, &dfout );
  orig_df = df = dfout;

  // Match?
  if( p )
  {
    if (!no_known) {

      if (add_timestamp) put_date(pts);
      a=(_u8*)&src;

      printf("%d.%d.%d.%d%s:%d - %s ",a[0],a[1],a[2],a[3],grab_name(a),
             sp,p->os);

      if (!no_osdesc) printf("%s ",p->desc);

      if (nat == 1) printf("(NAT!) "); else
        if (nat == 2) printf("(NAT2!) ");

      if (ecn) printf("(ECN) ");
      if (orig_df ^ df) printf("(firewall!) ");

      if (tos) {
        if (tos_desc) printf("[%s] ",tos_desc); else printf("[tos %d] ",tos);
      }

      if (p->generic) printf("[GENERIC] ");
      if (fuzzy_now) printf("[FUZZY] ");

      if (p->no_detail) printf("* "); else
        if (tstamp) printf("(up: %d hrs) ",tstamp/360000);

      if (always_sig || (p->generic && !no_unknown)) {

        if (!mode_oneline) printf("\n  ");
        printf("Signature: [");

        display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

        if (p->generic)
          printf(":%s:?] ",p->os);
        else
          printf("] ");

      }

      if (!no_extra && !p->no_detail) {
	a=(_u8*)&dst;
        if (!mode_oneline) printf("\n  ");

        if (fuzzy_now) 
          printf("-> %d.%d.%d.%d%s:%d (link: %s)",
               a[0],a[1],a[2],a[3],grab_name(a),dp,
               lookup_link(mss,1));
        else
          printf("-> %d.%d.%d.%d%s:%d (distance %d, link: %s)",
                 a[0],a[1],a[2],a[3],grab_name(a),dp,p->ttl - ttl,
                 lookup_link(mss,1));
      }

      if (pay && payload_dump) dump_payload(pay,plen - (pay - pkt));

      putchar('\n');
      if (full_dump) dump_packet(pkt,plen);

    }

   if (find_masq && !p->userland) {
     _s16 sc = p0f_findmasq(src,p->os,(p->no_detail || fuzzy_now) ? -1 : 
                            (p->ttl - ttl), mss, nat, orig_df ^ df,p-fp_db.sig,
                            tstamp ? tstamp / 360000 : -1);
     a=(_u8*)&src;
     if (sc > masq_thres) {
       if (add_timestamp) put_date(pts);
       printf(">> Masquerade at %u.%u.%u.%u%s: indicators at %d%%.",
              a[0],a[1],a[2],a[3],grab_name(a),sc);
       if (!mode_oneline) putchar('\n'); else printf(" -- ");
       if (masq_flags) {
         printf("   Flags: ");
         p0f_descmasq();
         putchar('\n');
       }
     }
   }

   if (use_cache || find_masq)
     p0f_addcache(src,dst,sp,dp,p->os,p->desc,(p->no_detail || fuzzy_now) ? 
                  -1 : (p->ttl - ttl),p->no_detail ? 0 : lookup_link(mss,0),
                  tos_desc, orig_df ^ df, nat, !p->userland, mss, p-fp_db.sig,
                  tstamp ? tstamp / 360000 : -1);

   fflush(0);

   return;
  }

  // No match

  if (mss & wss) {
    if ((wss % mss) && !(wss % 1460)) nat=1;
    else if ((wss % (mss+40)) && !(wss % 1500)) nat=2;
  }

  if (!no_unknown) { 
    if (add_timestamp) put_date(pts);
    a=(_u8*)&src;
    printf("%d.%d.%d.%d%s:%d - UNKNOWN [",a[0],a[1],a[2],a[3],grab_name(a),sp);

    display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

    printf(":?:?] ");

    if (fp_db.rst_mode) {

      /* Display a reasonable diagnosis of the RST+ACK madness! */
 
      switch (quirks & (QUIRK_RSTACK | QUIRK_SEQ0 | QUIRK_ACK)) {

        /* RST+ACK, SEQ=0, ACK=0 */
        case QUIRK_RSTACK | QUIRK_SEQ0:
          printf("(invalid-K0) "); break;

        /* RST+ACK, SEQ=0, ACK=n */
        case QUIRK_RSTACK | QUIRK_ACK | QUIRK_SEQ0: 
          printf("(refused) "); break;
 
        /* RST+ACK, SEQ=n, ACK=0 */
        case QUIRK_RSTACK: 
          printf("(invalid-K) "); break;

        /* RST+ACK, SEQ=n, ACK=n */
        case QUIRK_RSTACK | QUIRK_ACK: 
          printf("(invalid-KA) "); break; 

        /* RST, SEQ=n, ACK=0 */
        case 0:
          printf("(dropped) "); break;

        /* RST, SEQ=m, ACK=n */
        case QUIRK_ACK: 
          printf("(dropped 2) "); break;
 
        /* RST, SEQ=0, ACK=0 */
        case QUIRK_SEQ0: 
          printf("(invalid-0) "); break;

        /* RST, SEQ=0, ACK=n */
        case QUIRK_ACK | QUIRK_SEQ0: 
          printf("(invalid-0A) "); break; 

      }

    }

    if (nat == 1) printf("(NAT!) ");
      else if (nat == 2) printf("(NAT2!) ");

    if (ecn) printf("(ECN) ");

    if (tos) {
      if (tos_desc) printf("[%s] ",tos_desc); else printf("[tos %d] ",tos);
    }

    if (tstamp) printf("(up: %d hrs) ",tstamp/360000);

    if (!no_extra) {
      a=(_u8*)&dst;
      if (!mode_oneline) printf("\n  ");
      printf("-> %d.%d.%d.%d%s:%d (link: %s)",a[0],a[1],a[2],a[3],
	       grab_name(a),dp,lookup_link(mss,1));
    }

    if (use_cache)
      p0f_addcache(src,dst,sp,dp,0,0,-1,lookup_link(mss,0),tos_desc,
                   0,nat,0 /* not real, we're not sure */ ,mss,(_u32)-1,
                   tstamp ? tstamp / 360000 : -1);

    if (pay && payload_dump) dump_payload(pay,plen - (pay - pkt));
    putchar('\n');
    if (full_dump) dump_packet(pkt,plen);
    fflush(0);

  }
}


#define GET16(p) \
        ((_u16) *((_u8*)(p)+0) << 8 | \
         (_u16) *((_u8*)(p)+1) )



static void process(_u8* none, struct pcap_pkthdr *pph, _u8* packet) {
  struct timeval pts;
  struct ip_header * restrict iph;
  struct tcp_header * restrict tcph;
  fingerprint_t data;
  _u32 valid_fptypes = 0;
  _u8 * restrict end_ptr;

  if( fp_db.ack_mode ) { valid_fptypes = FPTYPE_SYNACK; }
  else if( fp_db.rst_mode ) { valid_fptypes = FPTYPE_RST; }
  else if( fp_db.open_mode ) { valid_fptypes = FPTYPE_STRAYACK; }
  else { valid_fptypes = FPTYPE_SYN; }

  packet_count++;

  if (dumper) pcap_dump((_u8*)dumper,pph,packet);

  /* Paranoia! */
  if (pph->len <= PACKET_SNAPLEN) end_ptr = packet + pph->len;
    else end_ptr = packet + PACKET_SNAPLEN;

  iph = (struct ip_header*)(packet+header_len);

  if (use_vlan && iph->ihl == 0x00)
    iph = (struct ip_header*)((_u8*)iph + 4);

  /* use either of the following if comparing fingerprint_t structures using memcmp, but usually unnecessary */
//  memset(&data, 0, sizeof(data));
//  memset(&data.tcp_options,  0, sizeof(data.tcp_options));
  

  if( parse   (&data , (_u8*)iph, end_ptr-((_u8*)iph), valid_fptypes) ) { return; }

  /* OpenBSD kludge */
  pts = *(struct timeval*)&pph->ts;

  find_match(
     /* total */ data.ip_total_len,
     /* DF */    data.ip_do_not_fragment,
     /* TTL */   data.ip_ttl,
     /* WSS */   data.tcp_window_size,
     /* src */   iph->saddr,
     /* dst */   iph->daddr,
     /* sp */    ntohs(data.tcph->sport),
     /* dp */    ntohs(data.tcph->dport),
     /* ocnt */  data.tcp_num_options,
     /* op */    data.tcp_options,
     /* mss */   data.tcp_opt_max_segment_size,
     /* wsc */   data.tcp_opt_window_scaling,
     /* tst */   data.tcp_opt_timestamp,
     /* TOS */   iph->tos,
     /* Q? */    data.quirks,
     /* ECN */   data.tcph->flags & (TH_ECE|TH_CWR),
     /* pkt */   (_u8*)iph,
     /* len */   end_ptr - (_u8*)iph,
     /* pay */   data.tcp_pay,
     /* ts */    pts
  );

#ifdef DEBUG_EXTRAS

  if (quirks & QUIRK_FLAGS || tcph->ack || tcph->_x2 || tcph->urg) 
    printf("  -- EXTRA TCP VALUES: ACK=0x%x, UNUSED=%d, URG=0x%x "
           "(flags = %x)\n",tcph->ack,tcph->_x2,tcph->urg,tcph->flags);
  fflush(0);

#endif /* DEBUG_EXTRAS */

}

/*void test_find_match()
{
  _u16 tot;
  _u8 df;
  _u8 ttl;
  _u16 wss;
  _u32 src;
  _u32 dst;
  _u16 sp;
  _u16 dp;
  _u8 ocnt;
  _u8 op[MAXOPT];
  _u16 mss;
  _u8 wsc;
  _u32 tstamp;
  _u8 tos;
  _u32 quirks;
  _u8 ecn;
  _u8* pkt;
  _u8 plen;
  _u8* pay;
  _u8 nat;
  _u8 dfout;

  tot    = 60;
  df     = 1;
  ttl    = 127;
  wss    = 5840;
  src    = 528618506;
  dst    = 159519754;
  sp     = 34817;
  dp     = 80;
  ocnt   = 5;
  op[0]  = 2;
  op[1]  = 4;
  op[2]  = 8;
  op[3]  = 1;
  op[4]  = 3;
  mss    = 1460;
  wsc    = 7;
  tstamp = 3210225599;
  tos    = 0;
  quirks = 0;
  ecn    = 0;
  pkt    = NULL;
  plen   = 60;
  pay    = NULL;

  const struct fp_entry* fp;
  fp = lookup_match( &fp_db, tot, df, ttl, wss, src, dst, sp, dp, ocnt, op, mss, wsc, 
                   tstamp, tos, quirks, use_fuzzy, &nat, &dfout );

  if( fp )
  {
    printf( "            nat    = %d \n"
            "            dfout  = %d \n"
            "            OS     = %s \n"
            "            OSver  = %s \n"
            , nat, dfout, fp->os, fp->desc );
  }
  else
  {
    printf( "            nat    = %d \n"
            "            dfout  = %d \n"
            "            OS     = UNKNOWN \n"
            "            OSver  = UNKNOWN \n"
            , nat, dfout );
  }
}*/


int main(int argc,char** argv) {
  _u8 buf[MAXLINE*4];
  _s32 r;
  _u8 errbuf[PCAP_ERRBUF_SIZE];
  
  _u8 check_collide;

#ifdef WIN32
  _u8 ebuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *d;
  _s32 adapter, i;
  while ((r = getopt(argc, argv, "f:i:s:o:w:c:T:e:XONVFDxKUqvtpArRlSdCLM")) != -1)
#else
  _s32 lsock=0;

  if (getuid() != geteuid())
    fatal("This program is not intended to be setuid.\n");
  
  while ((r = getopt(argc, argv, "f:i:s:o:Q:u:w:c:e:T:XOFNVDxKUqtRpvArlSdCM0")) != -1) 
#endif /* ^WIN32 */

    switch (r) {

      case 'f': config_file = optarg; break;

      case 'i': use_iface = optarg; break;

      case 's': use_dump = optarg; break;

      case 'w': write_dump = optarg; break;

      case 'c': query_cache = atoi(optarg); break;

      case 'o': if (!freopen(optarg,"a",stdout)) pfatal(optarg);
                use_logfile = 1;
                break;

      case 'V': masq_flags = 1;      break;
      case 'M': find_masq  = 1;      break;
      case 'T': masq_thres = atoi(optarg);
                if (masq_thres <= 0 || masq_thres > 200) fatal("Invalid -T value.\n");
                break;
		
      case 'e': capture_timeout = atoi(optarg);
                if (capture_timeout <= 0 ||capture_timeout > 10000) fatal("Invalid -e value.\n");
                break;

#ifndef WIN32
      case 'Q': use_cache  = optarg; break;
      case '0': port0_wild = 1;      break;
      case 'u': set_user   = optarg; break;
#endif /* !WIN32 */

      case 'r': do_resolve    = 1; break;
      case 'S': always_sig    = 1; break;
      case 'N': no_extra      = 1; break;
      case 'D': no_osdesc     = 1; break;
      case 'U': no_unknown    = 1; break;
      case 'K': no_known      = 1; break;
      case 'q': no_banner     = 1; break;
      case 'p': use_promisc   = 1; break;
      case 't': add_timestamp++;   break;
      case 'd': go_daemon     = 1; break;
      case 'v': use_vlan      = 1; break;
      case 'l': mode_oneline  = 1; break;
      case 'C': check_collide = 1; break;
      case 'x': full_dump     = 1; break;
      case 'X': payload_dump  = 1; break;
      case 'F': use_fuzzy     = 1; break;

      case 'A': use_rule = "tcp[13] & 0x17 == 0x12";
                fp_db.ack_mode = 1;
                break;

      case 'R': use_rule = "tcp[13] & 0x17 == 0x4 or tcp[13] & 0x17 == 0x14";
                fp_db.rst_mode = 1;
                break;

      case 'O': use_rule = "tcp[13] & 0x17 == 0x10";
                fp_db.open_mode = 1;
                break;

#ifdef WIN32

      case 'L':
        if (pcap_findalldevs(&alldevs, ebuf) == -1)
	  fatal("pcap_findalldevs: %s\n", ebuf);

      debug("\nInterface\tDevice\t\tDescription\n"
            "-------------------------------------------\n");

      for(i=1,d=alldevs;d;d=d->next,i++) {
        debug("%d %s",i, d->name);
        if (d->description)
	  debug("\t%s",d->description);
 	debug("\n");
      }
      exit(1);
      break;

#endif  /* WIN32 */

      default: usage(argv[0]);
    }
    
  if (!use_cache && port0_wild) fatal("-0 requires -Q (query mode).\n");

  if (use_logfile && !add_timestamp) add_timestamp = 1;

  if (use_iface && use_dump)
    fatal("-s and -i are mutually exclusive.\n");

  if (full_dump && mode_oneline)
    fatal("-x and -l are mutually exclusive.\n");

  if ((fp_db.ack_mode && fp_db.rst_mode) || (fp_db.ack_mode && fp_db.open_mode) ||
      (fp_db.open_mode && fp_db.ack_mode))
    fatal("-A, -R and -O are mutually exclusive.\n");

#ifdef DEBUG_EXTRAS
  if (mode_oneline || no_known || no_unknown || no_extra)
    debug("[!] WARNING: compiled with DEBUG_EXTRAS, -l, -K, -U, -N not "
          "compatible.\n");
#endif

  if (find_masq || use_cache)
    p0f_initcache(query_cache);
    
  if (!use_cache && !find_masq && no_known && no_unknown)
    fatal("-U and -K are mutually exclusive (except with -Q or -M).\n");

  if (!use_logfile && go_daemon)
    fatal("-d requires -o.\n");

  if (!no_banner) {
    debug("p0f - passive os fingerprinting utility, version " VER "\n"
          "(C) M. Zalewski <lcamtuf@dione.cc>, W. Stearns <wstearns@pobox.com>\n");  
#ifdef WIN32
    debug("WIN32 port (C) M. Davis <mike@datanerds.net>, K. Kuehl <kkuehl@cisco.com>\n");
#endif /* WIN32 */

    if (use_fuzzy && fp_db.rst_mode)
      debug("[!] WARNING: It is a bad idea to combine -F and -R.\n");

  }

  load_config(&fp_db, config_file, check_collide);

  if (argv[optind] && *(argv[optind])) {
    sprintf(buf,"(%s) and (%.3000s)",use_rule,argv[optind]);
    use_rule = buf;
  } 

  if (use_vlan) {
    _u8* x = strdup(use_rule);
    sprintf(buf,"(%.1000s) or (vlan and (%.1000s))",x,x);
    free(x);
    use_rule = buf;
  }

  signal(SIGINT,&die_nicely);
  signal(SIGTERM,&die_nicely);

#ifndef WIN32
  signal(SIGHUP,&die_nicely);
  signal(SIGQUIT,&die_nicely);

  if (use_cache) {
    struct sockaddr_un x;
    
    lsock = socket(PF_UNIX,SOCK_STREAM,0);
    if (lsock < 0) pfatal("socket");

    memset(&x,0,sizeof(x));
    x.sun_family = AF_UNIX;
    strncpy(x.sun_path,use_cache,63);
    unlink(use_cache);
    if (bind(lsock,(struct sockaddr*)&x,sizeof(x))) pfatal(use_cache);
    if (listen(lsock,10)) pfatal("listen");

  }
#endif /* !WIN32 */

  if (use_dump) {
    if (!(pt=pcap_open_offline(use_dump, errbuf))) 
      fatal("pcap_open_offline failed: %s\n",errbuf);
  } else {

#ifdef WIN32
    if (pcap_findalldevs(&alldevs, ebuf) == -1)
      fatal("pcap_findalldevs: %s\n", ebuf);
	
    if (!use_iface) {
      d = alldevs;
    } else {
      adapter = atoi(use_iface);
      for(i=1, d=alldevs; adapter && i < adapter && d; i++, d=d->next);
      if (!d) fatal("Unable to find adapter %d\n", adapter);
    }

    use_iface = d->name;

#else
    if (!use_iface) use_iface=pcap_lookupdev(errbuf);
#endif /* ^WIN32 */

    if (!use_iface) use_iface = "lo";

    /* We do not rely on pcap timeouts - they suck really bad. Of
       course, the documentation sucks, and if you use the timeout
       of zero, things will break. */
    
    if (!(pt=pcap_open_live(use_iface,PACKET_SNAPLEN,use_promisc,capture_timeout,errbuf))) 
      fatal("pcap_open_live failed: %s\n",errbuf);
  }

  set_header_len(pcap_datalink(pt));

  if (pcap_compile(pt, &flt, use_rule, 1, 0))
    if (strchr(use_rule,'(')) {
      pcap_perror(pt,"pcap_compile");
      debug("See man tcpdump or p0f README for help on bpf filter expressions.\n");
      exit(1);
    }

  if (!no_banner) {
    debug("p0f: listening (%s) on '%s', %d sigs (%d generic, cksum %08X), rule: '%s'.\n",
          fp_db.ack_mode ? "SYN+ACK" : fp_db.rst_mode ? "RST+" :
          fp_db.open_mode ? "OPEN" : "SYN",
          use_dump?use_dump:use_iface,fp_db.sigcnt,fp_db.gencnt,fp_db.file_cksum,
          argv[optind]?argv[optind]:"all");

    if (use_cache) debug("[*] Accepting queries at socket %s (timeout: %d s).\n",use_cache,QUERY_TIMEOUT);
    if (find_masq) debug("[*] Masquerade detection enabled at threshold %d%%.\n",masq_thres);
    
  }
  
  pcap_setfilter(pt, &flt);

  if (write_dump) {
    if (!(dumper=pcap_dump_open(pt, write_dump))) {
      pcap_perror(pt,"pcap_dump_open");
      exit(1);
    }
  }
  
  /* For p0f statistics */
  if (fp_db.ack_mode) operating_mode = 'A'; 
  else if (fp_db.rst_mode) operating_mode = 'R';
  else if (fp_db.open_mode) operating_mode = 'O';
  else operating_mode = 'S';

#ifndef WIN32

  if (set_user) {
    struct passwd* pw;

    if (geteuid()) fatal("only root can use -u.\n");

    tzset();

    pw = getpwnam(set_user);
    if (!pw) fatal("user %s not found.\n",set_user);
    
    if (use_cache && chown(use_cache,pw->pw_uid,pw->pw_gid)) 
      debug("[!] Failed to set ownership of query socket.");
 
    if (chdir(pw->pw_dir)) pfatal(pw->pw_dir);
    if (chroot(pw->pw_dir)) pfatal("chroot");
    chdir("/");

    if (initgroups(pw->pw_name,pw->pw_gid)) pfatal("initgroups");
    if (setgid(pw->pw_gid)) pfatal("setgid");
    if (setuid(pw->pw_uid)) pfatal("setuid");

    if (getegid() != pw->pw_gid || geteuid() != pw->pw_uid)
      fatal("failed to setuid/setgid to the desired UID/GID.\n");

  }

#endif /* !WIN32 */

  if (go_daemon) {

#ifndef WIN32
    _s32 f;
    struct timeval tv;
    FILE* pid_fd;
    fflush(0);
    f = fork();
    if (f<0) pfatal("fork() failed");
    if (f) exit(0);
    dup2(1,2);
    close(0);
    chdir("/");
    setsid();
    signal(SIGHUP,SIG_IGN);
    
    if ((pid_fd = fopen(PID_PATH, "w"))) {
      fprintf(pid_fd, "%d", getpid());
      fclose(pid_fd);
    }
    
    printf("--- p0f " VER " resuming operations at ");
    gettimeofday(&tv, (struct timezone*)0);
    put_date(tv);
    printf("---\n");
    fflush(0);
#else
    fatal("daemon mode is not support in the WIN32 version.\n");
#endif /* ^WIN32 */

  }

  st_time = time(0);

#ifndef WIN32 

  if (use_cache) {

    _s32 mfd,max;

    mfd = pcap_fileno(pt);

    max = 1 + (mfd > lsock ? mfd : lsock);

    while (1) {
      fd_set f,e;

      FD_ZERO(&f);
      FD_SET(mfd,&f);
      FD_SET(lsock,&f);

      FD_ZERO(&e);
      FD_SET(mfd,&e);
      FD_SET(lsock,&e);

      /* This is the neat way to do it; pcap timeouts are broken
         on many platforms, Linux always resumes recvfrom() on the
	 raw socket, even with no SA_RESTART, it's a mess... select()
	 is rather neutral. */

      select(max,&f,0,&e,0);

      if (FD_ISSET(mfd, &f) || FD_ISSET(mfd,&e))
        if (pcap_dispatch(pt,-1,(pcap_handler)&process,0) < 0) break;

      if (FD_ISSET(lsock,&f)) {
	struct timeval tv;
        struct p0f_query q;
        _s32 c;

        if ((c=accept(lsock,0,0))<0) continue;

        FD_ZERO(&f);
        FD_SET(c,&f);
        tv.tv_sec  = QUERY_TIMEOUT; 
        tv.tv_usec = 0;

        if (select(c+1,&f,0,&f,&tv)>0)
          if (recv(c,&q,sizeof(q),MSG_NOSIGNAL) == sizeof(q)) 
            p0f_handlequery(c,&q,port0_wild);

        shutdown(c,2); 
        close(c);

      }

      if (FD_ISSET(lsock,&e)) 
        fatal("Query socket error.\n");

    }

  } else 
#endif /* !WIN32 */

  pcap_loop(pt,-1,(pcap_handler)&process,0);

  pcap_close(pt);
  if (dumper) pcap_dump_close(dumper);

  if (use_dump) debug("[+] End of input file.\n");
    else fatal("Network is down.\n");

	/*test_find_match();*/

  return 0;

}

