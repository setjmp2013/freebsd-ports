## Makefile.am for the "p0f" subdir
##
#
# Make a libtool library called p0f

lib_LTLIBRARIES = libp0f.la

libp0f_la_SOURCES= \
                   crc32.c \
                   p0f-config.c \
                   p0f-lookup.c \
                   p0f-query.c \
                   p0f-parse.c

libp0f_la_LDFLAGS= \ #-version-info $(VERSION) \
                   -release $(VERSION)

## AM_ variables are just like the normal variables.  Because variables like
## CFLAGS and CPPFLAGS are reserved for users at compile time AM_ variables
## are shadow variables with the same effect.
PROJECT_INCLUDES = -I@top_srcdir@/include -I@top_builddir@/include
AM_CFLAGS = $(all_includes) $(PROJECT_INCLUDES)

