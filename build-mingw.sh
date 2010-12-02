#!/bin/sh

# TODO: Integrate this into build.sh for there must be one and only one
#	way to compile gtk-gnutella.
#
# Simple compilation wrapper to build gtk-gnutella on Windows with MINGW.
# This script is meant to be run through the MSYS shell from MINGW.
#
# Assumes that /mingw/lib holds the system libraries.
# glib/GTK installed in /mingw/lib/gtk (bundled .zip with all dependencies)
# libxml2 installed in /mingw/lib/xml2
# regex installed in /mingw/lib/regex
#
# If not, adjust the PATH below, along with INCDIRS & LIBDIRS

# The PATH is set so that pkg-config and xml2-config can be found
PATH=$PATH${PATH:+:}/mingw/lib/gtk/bin:/mingw/lib/xml2/bin
export PATH

OPTIMIZE='-O2 -g'
INCDIRS='-I/mingw/lib/regex/include -I/mingw/lib/gtk/include'
LIBDIRS='-L/mingw/lib/regex/lib -L/mingw/lib/gtk/lib'
LIBS='-lwsock32 -lws2_32 -lregex -lz -liconv -lws2_32
	-lpowrprof -lpsapi -lkernel32'

# In case thet are too long one day, avoid line breaks
INCDIRS=`echo $INCDIRS`
LIBDIRS=`echo $LIBDIRS`
LIBS=`echo $LIBS`

./Configure -der -Dgtkversion=2 -Dcc=gcc \
	-Dd_select -Dd_msghdr_msg_flags -Dd_getaddrinfo \
	-Doptimize="$OPTIMIZE" \
	-Dccflags="-DMINGW32 $INCDIRS" -Dldflags="$LIBDIRS" -Dlibs="$LIBS"
