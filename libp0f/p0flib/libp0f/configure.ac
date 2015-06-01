AC_PREREQ(2.60)
AC_INIT([libp0f], [2.0.8])

AM_INIT_AUTOMAKE([libp0f], [2.0.8])

AC_CONFIG_HEADERS([include/p0f/config.h])
AH_BOTTOM([#include "p0f/config-p0f.h"])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

AC_C_RESTRICT
AC_C_CONST

# Install fingerprint files into /etc
AC_SUBST([sysconfdir], [/etc])

dnl ----------------------------------------------------------------------
dnl Check for libpcap
dnl ----------------------------------------------------------------------
AC_ARG_WITH(libpcap,
    AS_HELP_STRING([--with-libpcap=path],[location of libpcap]),[
    if test "x$withval" != "xno"; then
        if test -d ${withval}; then
            if test -d ${withval}/lib; then
                CFLAGS="-I${withval}/include $CFLAGS"
                CPPFLAGS="-I${withval}/include $CPPFLAGS"
                LIBS="-L${withval}/lib -lpcap $LIBS"
                if test "x$target_os" = "xlinux" -o \
                        "x$target_os" = "xlinux-gnu"; then
                    LIBS="-Wl,--rpath -Wl,${withval}/lib $LIBS"
                fi
            else
                LIBS="-L${withval} -lpcap $LIBS"
                if test "x$target_os" = "xlinux" -o \
                        "x$target_os" = "xlinux-gnu"; then
                    LIBS="-Wl,--rpath -Wl,${withval} $LIBS"
                fi
            fi
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-libpcap=${withval}"
        fi
    fi
    ],[
        AC_CHECK_LIB(pcap, pcap_open_offline,
            [],
            [AC_MSG_ERROR([cannot locate required PCAP library, try the --with-libpcap option])]
            )
        AC_CHECK_HEADERS(pcap.h,
            [],
            [AC_MSG_ERROR([cannot locate the required pcap.h header file])]
            )
    ]
)

AC_CONFIG_FILES([ Makefile 
                  src/Makefile 
                  src/library/Makefile 
                  src/app/Makefile 
                  include/Makefile
                  etc/Makefile
                  libp0f.pc
                ])

AC_OUTPUT


