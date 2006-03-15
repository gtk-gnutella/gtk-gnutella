#! /bin/sh -x

# $Id$
#
# Purpose:
#
#	Build gtk-gnutella without a GUI. This is called "topless mode".
#
# Usage:
#
#	Execute this shell script in a directory that contains
#	a copy of the gtk-gnutella sources or use lndir:
#
#	$ lndir /path/to/gtk-gnutella/
#
#	The reason for using a "copy" is that the sources respectively
#	the directory structure are slightly modified. Thus, building
#	gtk-gnutella with a GUI will fail after this.

./Configure -Oders \
	-Dccflags="$CFLAGS -DUSE_TOPLESS" \
	-Dldflags="${LDFLAGS:--Unone}" \
	-Dgtkversion=2 || exit

# gui_property.c requires special treatment as it's generated and doesn't
# conditionally skip code when USE_TOPLESS is defined. The file (or rather
# the link when using lndir) is removed and an empty file is used as
# replacement.
rm -f src/if/gui_property.c || exit
echo > src/if/gui_property.c || exit

# Prevent that gui_props.ag is re-evaluated which would regenerated the
# above file.
touch src/if/gui_property.h src/if/gui_property_priv.h || exit

# Fake building of GTK2 UI code by creating an empty library just to
# meet the build rules of the Makefile.
(
	cd src/ui || exit 1
	mv gtk gtk.old

	ln -s topless gtk && \
	cd gtk && \
	printf "all depend clean clobber install:\n\t\n" > Makefile && \
	mkdir -p gtk2 && \
	cp Makefile gtk2 && \
	echo > blah.c && \
	cc -c blah.c && \
	ar r libgtkx.a blah.o && \
	ar r libgtk-common.a blah.o
) || exit

# Make sure neither USE_GTK1 nor USE_GTK2 is defined
sed 's/^#define USE_GTK.*$//' config.h > config.h.new || exit
cp config.h.new config.h || exit

make depend || exit

# Remove all references to GUI-related libraries from the Makefile
# which might have been added during Configure (gtk-config etc.)
sed '
s/-latk[a-zA-Z0-9._-]*//g;
s/-lcairo[a-zA-Z0-9._-]*//g;
s/-lgdk[a-zA-Z0-9._-]*//g;
s/-lgtk[a-zA-Z0-9._-]*//g;
s/-lpango[a-zA-Z0-9._-]*//g;
s/-lX[a-zA-Z0-9._-]*//g;
' src/Makefile > src/Makefile.new || exit
cp src/Makefile.new src/Makefile || exit

make

exit
