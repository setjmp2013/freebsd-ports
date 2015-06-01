## Makefile.am for the "p0f" subdir
##
#

bin_PROGRAMS = p0f

p0f_SOURCES = p0f.c

# TODO: figure out USE_BPF
USE_BPF = pcap-bpf.h

p0f_CFLAGS = -I@top_srcdir@/include -I@top_builddir@/include \
             -DUSE_BPF=\"$(USE_BPF)\"

p0f_LDFLAGS = -L../library/.libs

p0f_LDADD = -lp0f -lpcap


## AM_ variables are just like the normal variables.  Because variables like
## CFLAGS and CPPFLAGS are reserved for users at compile time AM_ variables
## are shadow variables with the same effect.
AM_CFLAGS   = $(all_includes)

