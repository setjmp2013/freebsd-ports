#!/bin/sh

# Add a4 dir and files
libtoolize

# Create required autotools files
touch NEWS README AUTHORS ChangeLog

# Regenerate aclocal, autoconf, and automake files
autoreconf --install


