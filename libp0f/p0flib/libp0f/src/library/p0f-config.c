#include "p0f/public.h"
#include "p0f/tcp.h"
#include "p0f/crc32.h"
#include "p0f/private.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

static _u8 problems; /* collide, load_config */

void collide(const struct fp_database* db, _u32 id) {
  _u32 i,j;
  _u32 cur;
  const struct fp_entry* sig = db->sig;

  if (sig[id].ttl % 32 && sig[id].ttl != 255 && sig[id].ttl % 30) {
    problems=1;
    debug("[!] Unusual TTL (%d) for signature '%s %s' (line %d).\n",
          sig[id].ttl,sig[id].os,sig[id].desc,sig[id].line);
  }

  for (i=0;i<id;i++) {

    if (!strcmp(sig[i].os,sig[id].os) && 
        !strcmp(sig[i].desc,sig[id].desc)) {
      problems=1;
      debug("[!] Duplicate signature name: '%s %s' (line %d and %d).\n",
            sig[i].os,sig[i].desc,sig[i].line,sig[id].line);
    }

    /* If TTLs are sufficiently away from each other, the risk of
       a collision is lower. */
    if (abs((_s32)sig[id].ttl - (_s32)sig[i].ttl) > 25) continue;

    if (sig[id].df ^ sig[i].df) continue;
    if (sig[id].zero_stamp ^ sig[i].zero_stamp) continue;

    /* Zero means >= PACKET_BIG */
    if (sig[id].size) { if (sig[id].size ^ sig[i].size) continue; }
      else if (sig[i].size < PACKET_BIG) continue;

    if (sig[id].optcnt ^ sig[i].optcnt) continue;
    if (sig[id].quirks ^ sig[i].quirks) continue;

    switch (sig[id].wsize_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsize;

do_const:

        switch (sig[i].wsize_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsize) continue; 
            break;

          case MOD_CONST: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsize) continue;
            break;

          case MOD_MSS: /* Current: const, prev: mod MSS */

            if (sig[i].mss_mod || sig[i].wsize *
	       (sig[i].mss ? sig[i].mss : 1460 ) != cur)
              continue;

            break;

          case MOD_MTU: /* Current: const, prev: mod MTU */

            if (sig[i].mss_mod || sig[i].wsize * (
	        (sig[i].mss ? sig[i].mss : 1460 )+40) != cur)
              continue;

            break;

        }
        
        break;

      case 1: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (sig[i].wsize_mod != MOD_CONST) continue;
        if (sig[id].wsize % sig[i].wsize) continue;

        break;

      case MOD_MSS: /* Current is modulo MSS */
  
        /* There's likely a problem only if the previous one is close
           to '*'; we do not check known MTUs, because this particular
           signature can be made with some uncommon MTUs in mind. The
           problem would also appear if current signature has a fixed
           MSS. */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize >= 8) {
          if (!sig[id].mss_mod) {
            cur = (sig[id].mss ? sig[id].mss : 1460 ) * sig[id].wsize;
            goto do_const;
          }
          continue;
        }

        break;

      case MOD_MTU: /* Current is modulo MTU */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize <= 8) {
          if (!sig[id].mss_mod) {
            cur = ( (sig[id].mss ? sig[id].mss : 1460 ) +40) * sig[id].wsize;
            goto do_const;
          }
          continue;
        }
  
        break;

    }

    /* Same for wsc */
    switch (sig[id].wsc_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsc;

        switch (sig[i].wsc_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsc) continue; 
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsc) continue;
            break;

        }
        
        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (!sig[i].wsc_mod) continue;
        if (sig[id].wsc % sig[i].wsc) continue;

        break;

     }

    /* Same for mss */
    switch (sig[id].mss_mod) {

      case 0: /* Current: const */

        cur=sig[id].mss;

        switch (sig[i].mss_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].mss) continue; 
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].mss) continue;
            break;

        }
        
        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (!sig[i].mss_mod) continue;
        if ((sig[id].mss ? sig[id].mss : 1460 ) % 
	    (sig[i].mss ? sig[i].mss : 1460 )) continue;

        break;

     }

     /* Now check option sequence */

    for (j=0;j<sig[id].optcnt;j++)
      if (sig[id].opt[j] ^ sig[i].opt[j]) goto reloop;

    problems=1;
    debug("[!] Signature '%s %s' (line %d)\n"
          "    is already covered by '%s %s' (line %d).\n",
          sig[id].os,sig[id].desc,sig[id].line,sig[i].os,sig[i].desc,
          sig[i].line);

reloop:

    ;

  }

}


void load_config(struct fp_database* db, _u8* file, _u8 check_collide) {
  _u32 ln=0;
  _u8 buf[MAXLINE];
  _u8* p;
  struct fp_entry* sig = db->sig;
  FILE* c = fopen(file?file:(_u8*)
            (db->ack_mode?SYNACK_DB:(db->rst_mode?RST_DB:(db->open_mode?OPEN_DB:SYN_DB))),
            "r");

  if (!c) {
    if (!file) load_config(db, db->ack_mode? CONFIG_DIR "/" SYNACK_DB :
                                     ( db->rst_mode ? CONFIG_DIR "/" RST_DB : 
                                     ( db->open_mode ? CONFIG_DIR "/" OPEN_DB : 
                                       CONFIG_DIR "/" SYN_DB )) 
                           , check_collide );
      else pfatal(file);
    return;
  }

  while ((p=fgets(buf,sizeof(buf),c))) {
    _u32 l;

    _u8 obuf[MAXLINE],genre[MAXLINE],desc[MAXLINE],quirks[MAXLINE];
    _u8 w[MAXLINE],sb[MAXLINE];
    _u8* gptr = genre;
    _u32 t,d,s;
    struct fp_entry* e;
    
    db->file_cksum ^= crc32(buf, strlen(buf));
      
    ln++;

    /* Remove leading and trailing blanks */
    while (isspace(*p)) p++;
    l=strlen(p);
    while (l && isspace(*(p+l-1))) *(p+(l--)-1)=0;
	
    /* Skip empty lines and comments */
    if (!l) continue;
    if (*p == '#') continue;

    if (sscanf(p,"%[0-9%*()ST]:%d:%d:%[0-9()*]:%[^:]:%[^ :]:%[^:]:%[^:]",
                  w,         &t,&d,sb,     obuf, quirks,genre,desc) != 8)
      fatal("Syntax error in config line %d.\n",ln);

    gptr = genre;

    if (*sb != '*') {
      if (db->open_mode) 
        fatal("Packet size must be '*' in -O mode (line %d).\n",ln);
      s = atoi(sb); 
    } else s = 0;

reparse_ptr:

    switch (*gptr) {
      case '-': sig[db->sigcnt].userland = 1; gptr++; goto reparse_ptr;
      case '*': sig[db->sigcnt].no_detail = 1; gptr++; goto reparse_ptr;
      case '@': sig[db->sigcnt].generic = 1; gptr++; db->gencnt++; goto reparse_ptr;
      case 0: fatal("Empty OS genre in line %d.\n",ln);
    }

    sig[db->sigcnt].os     = strdup(gptr);
    sig[db->sigcnt].desc   = strdup(desc);
    sig[db->sigcnt].ttl    = t;
    sig[db->sigcnt].size   = s;
    sig[db->sigcnt].df     = d;
 
    if (w[0] == '*') {
      sig[db->sigcnt].wsize = 1;
      sig[db->sigcnt].wsize_mod = MOD_CONST;
    } else if (tolower(w[0]) == 's') {
      sig[db->sigcnt].wsize_mod = MOD_MSS;
      if (!isdigit(*(w+1))) fatal("Bad Snn value in WSS in line %d.\n",ln);
      sig[db->sigcnt].wsize = atoi(w+1);
    } else if (tolower(w[0]) == 't') {
      sig[db->sigcnt].wsize_mod = MOD_MTU;
      if (!isdigit(*(w+1))) fatal("Bad Tnn value in WSS in line %d.\n",ln);
      sig[db->sigcnt].wsize = atoi(w+1);
    } else if (w[0] == '%') {
      if (!(sig[db->sigcnt].wsize = atoi(w+1)))
        fatal("Null modulo for window size in config line %d.\n",ln);
      sig[db->sigcnt].wsize_mod = MOD_CONST;
    } else sig[db->sigcnt].wsize = atoi(w);

    /* Now let's parse options */

    p=obuf;

    sig[db->sigcnt].zero_stamp = 1;

    if (*p=='.') p++;

    while (*p) {
      _u8 optcnt = sig[db->sigcnt].optcnt;
      switch (tolower(*p)) {

        case 'n': sig[db->sigcnt].opt[optcnt] = TCPOPT_NOP;
                  break;

        case 'e': sig[db->sigcnt].opt[optcnt] = TCPOPT_EOL;
                  if (*(p+1)) 
                    fatal("EOL not the last option (line %d).\n",ln);
                  break;

        case 's': sig[db->sigcnt].opt[optcnt] = TCPOPT_SACKOK;
                  break;

        case 't': sig[db->sigcnt].opt[optcnt] = TCPOPT_TIMESTAMP;
                  if (*(p+1)!='0') {
                    sig[db->sigcnt].zero_stamp=0;
                    if (isdigit(*(p+1))) 
                      fatal("Bogus Tstamp specification in line %d.\n",ln);
                  }
                  break;

        case 'w': sig[db->sigcnt].opt[optcnt] = TCPOPT_WSCALE;
                  if (p[1] == '*') {
                    sig[db->sigcnt].wsc = 1;
                    sig[db->sigcnt].wsc_mod = MOD_CONST;
                  } else if (p[1] == '%') {
                    if (!(sig[db->sigcnt].wsc = atoi(p+2)))
                      fatal("Null modulo for wscale in config line %d.\n",ln);
                    sig[db->sigcnt].wsc_mod = MOD_CONST;
                  } else if (!isdigit(*(p+1)))
                    fatal("Incorrect W value in line %d.\n",ln);
                  else sig[db->sigcnt].wsc = atoi(p+1);
                  break;

        case 'm': sig[db->sigcnt].opt[optcnt] = TCPOPT_MAXSEG;
                  if (p[1] == '*') {
                    sig[db->sigcnt].mss = 1;
                    sig[db->sigcnt].mss_mod = MOD_CONST;
                  } else if (p[1] == '%') {
                    if (!(sig[db->sigcnt].mss = atoi(p+2)))
                      fatal("Null modulo for MSS in config line %d.\n",ln);
                    sig[db->sigcnt].mss_mod = MOD_CONST;
                  } else if (!isdigit(*(p+1)))
                    fatal("Incorrect M value in line %d.\n",ln);
                  else sig[db->sigcnt].mss = atoi(p+1);
                  break;

        /* Yuck! */
        case '?': if (!isdigit(*(p+1)))
                    fatal("Bogus ?nn value in line %d.\n",ln);
                  else sig[db->sigcnt].opt[optcnt] = atoi(p+1);
                  break;

        default: fatal("Unknown TCP option '%c' in config line %d.\n",*p,ln);
      }

      if (++sig[db->sigcnt].optcnt >= MAXOPT) 
        fatal("Too many TCP options specified in config line %d.\n",ln);

      /* Skip separators */
      do { p++; } while (*p && !isalpha(*p) && *p != '?');

    }
 
    sig[db->sigcnt].line = ln;

    p = quirks;

    while (*p) 
      switch (toupper(*(p++))) {
        case 'E': 
          fatal("Quirk 'E' (line %d) is obsolete. Remove it, append E to the "
          "options.\n",ln);

        case 'K': 
	  if (!db->rst_mode) fatal("Quirk 'K' (line %d) is valid only in RST+ (-R)"
	      " mode (wrong config file?).\n",ln);
  	  sig[db->sigcnt].quirks |= QUIRK_RSTACK; 
	  break;

        case 'D': 
          if (db->open_mode) fatal("Quirk 'D' (line %d) is not valid in OPEN (-O) "
                               "mode (wrong config file?).\n",ln);
          sig[db->sigcnt].quirks |= QUIRK_DATA; 
 	  break;
 
        case 'Q': sig[db->sigcnt].quirks |= QUIRK_SEQEQ; break;
        case '0': sig[db->sigcnt].quirks |= QUIRK_SEQ0; break;
        case 'P': sig[db->sigcnt].quirks |= QUIRK_PAST; break;
        case 'Z': sig[db->sigcnt].quirks |= QUIRK_ZEROID; break;
        case 'I': sig[db->sigcnt].quirks |= QUIRK_IPOPT; break;
        case 'U': sig[db->sigcnt].quirks |= QUIRK_URG; break;
        case 'X': sig[db->sigcnt].quirks |= QUIRK_X2; break;
        case 'A': sig[db->sigcnt].quirks |= QUIRK_ACK; break;
        case 'T': sig[db->sigcnt].quirks |= QUIRK_T2; break;
        case 'F': sig[db->sigcnt].quirks |= QUIRK_FLAGS; break;
        case '!': sig[db->sigcnt].quirks |= QUIRK_BROKEN; break;
        case '.': break;
        default: fatal("Bad quirk '%c' in line %d.\n",*(p-1),ln);
      }

    e = db->bh[SIGHASH(s,sig[db->sigcnt].optcnt,sig[db->sigcnt].quirks,d)];

    if (!e) {
      db->bh[SIGHASH(s,sig[db->sigcnt].optcnt,sig[db->sigcnt].quirks,d)] = sig + db->sigcnt;
    } else {
      while (e->next) e = e->next;
      e->next = sig + db->sigcnt;
    } 

    if (check_collide) collide(db, db->sigcnt);

    if (++(db->sigcnt) >= MAXSIGS)
      fatal("Maximum signature count exceeded.\n");

  }

  fclose(c);

#ifdef DEBUG_HASH
  { 
    int i;
    struct fp_entry* p;
    printf("Hash table layout: ");
    for (i=0;i<16;i++) {
      int z=0;
      p = db->bh[i];
      while (p) { p=p->next; z++; }
      printf("%d ",z);
    }
    putchar('\n');
  }
#endif /* DEBUG_HASH */

  if (check_collide && !problems) 
    debug("[+] Signature collision check successful.\n");

  if (!db->sigcnt)
    debug("[!] WARNING: no signatures loaded from config file.\n");

}
