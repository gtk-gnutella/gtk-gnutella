#! /bin/sh

# This is a simple wrapper script to make compiling a bit easier.
# Configure is too verbose and curious about many things and not
# sufficiently eloquent about others such as available options.

# Bail out on unexpected errors
set -e

build_bindir=
build_cc=
build_ccflags=
build_datadir=
build_dbus=
build_ipv6=
build_ldflags=
build_localedir=
build_nls=
build_official=
build_optimize=
build_prefix=
build_ui=
build_yacc=
build_install=

while [ $# -gt 0 ]; do
	case "$1" in
	--prefix=*)	build_prefix="-D '${1##--}'";;
	--yacc=*)	build_yacc="-D '${1##--}'";;
	--unofficial)	build_official='-Dofficial=false';;
	--topless)	build_ui='-D d_headless';;
	--gtk1)		build_ui='-D gtkversion=1';;
	--gtk2)		build_ui='-D gtkversion=2';;
	--disable-dbus)	build_dbus='-U d_dbus -D dbus=false';;
	--disable-nls)	build_nls='-U d_enablenls';;
	--disable-ipv6)	build_ipv6='-U d_ipv6';;
	--) 		break
			;;
	*)
echo The following switches are available:
echo
echo '  --prefix=PATH    Path prefix used for installing files. [/usr/local]'
echo '  --gtk2           Use Gtk+ 2.x for the user interface [default].'
echo '  --gtk1           Use the deprecated Gtk+ 1.2 for the user interface.'
echo '  --topless        Compile for topless use (no graphical user interface).'
echo '  --disable-nls    Disable NLS (native language support).'
echo '  --disable-ipv6   Do not use IPv6 even if supported.'
echo '  --yacc=TOOL      Either "yacc" or "bison".'
echo '  --bindir=PATH    Directory used for installing executables.'
echo '  --localedir=PATH Directory used for installing locale data.'
echo '  --datadir=PATH   Directory used for installing application data.'
echo '  --mandir=PATH    Directory used for installing manual pages.'
echo
echo 'The following environment variables are honored:'
echo
echo '  CC, CFLAGS, LDFLAGS, PREFIX'
			exit 1
			;;
	esac
	shift
done

if [ "X$build_yacc" = X ]; then
	build_yacc="-D 'yacc=bison'"
	which yacc >/dev/null 2>&1 && build_yacc="-D 'yacc=yacc'"
fi

if [ "X$build_cc" = X ] && [ "X$CC" != X ]; then
	build_cc="-D 'cc=$CC'"
fi

if [ "X$build_ccflags" = X ] && [ "X$CFLAGS" != X ]; then
	build_ccflags="-D 'ccflags=$CFLAGS'"
fi

if [ "X$build_ldflags" = X ] && [ "X$LDFLAGS" != X ]; then
	build_ldflags="-D 'ldflags=$LDFLAGS'"
fi

if [ "X$build_prefix" = X ]; then
	if [ "X$PREFIX" != X ]; then
		build_prefix=$PREFIX
	else
		build_prefix=/usr/local
	fi
fi

if [ "X$build_bindir" = X ]; then
	build_bindir="$build_prefix/bin"
fi

if [ "X$build_mandir" = X ]; then
	build_mandir="$build_prefix/man"
fi

if [ "X$build_datadir" = X ]; then
	build_datadir="$build_prefix/share"
fi

if [ "X$build_localedir" = X ]; then
	build_localedir="$build_prefix/share/locale"
fi

if [ "X$build_official" = X ]; then
	build_official="-D 'official=true'"
fi

if [ "X$build_ui" = X ]; then
	build_ui='-D gtkversion=2'
fi

build_prefix="-D 'prefix=${build_prefix}'"
build_bindir="-D 'bindir=${build_bindir}'"
build_mandir="-D 'sysman=$build_mandir/man1'"
build_datadir="-D 'bindir=${build_datadir}'"
build_localedir="-D 'localdir=${build_localedir}'"

make clobber >/dev/null 2>&1 || : ignore failure

/bin/sh ./Configure -Oders \
	${build_prefix} \
	${build_bindir} \
	${build_mandir} \
	${build_datadir} \
	${build_localedir} \
	${build_ui} \
	${build_ccflags} \
	${build_ldflags} \
	${build_nls} \
	${build_yacc}

make

echo 'Run "make install" to install gtk-gnutella.'
exit

