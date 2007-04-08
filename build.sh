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
build_gnutls=
build_ipv6=
build_ldflags=
build_localedir=
build_nls=
build_official=
build_prefix=
build_ui=
build_yacc=

while [ $# -gt 0 ]; do
	case "$1" in
	--bindir=*)		build_bindir="-D '${1##--}'";;
	--datadir=*)		build_datadir="-D '${1##--}'";;
	--disable-dbus)		build_dbus='-U d_dbus';;
	--disable-gnutls)	build_gnutls='-U d_gnutls';;
	--disable-ipv6)		build_ipv6='-U d_ipv6';;
	--disable-nls)		build_nls='-U d_enablenls';;
	--gtk1)			build_ui='-D gtkversion=1';;
	--gtk2)			build_ui='-D gtkversion=2';;
	--localedir=*)		build_localedir="-D '${1##--}'";;
	--mandir=*)		build_mandir="-D '${1##--}'";;
	--prefix=*)		build_prefix="-D '${1##--}'";;
	--topless)		build_ui='-D d_headless';;
	--unofficial)		build_official='-D official=false';;
	--yacc=*)		build_yacc="-D '${1##--}'";;
	--) 		break
			;;
	*)
echo The following switches are available:
echo
echo '  --prefix=PATH    Path prefix used for installing files. [/usr/local]'
echo '  --gtk2           Use Gtk+ 2.x for the user interface [default].'
echo '  --gtk1           Use the deprecated Gtk+ 1.2 for the user interface.'
echo '  --topless        Compile for topless use (no graphical user interface).'
echo '  --disable-dbus   Do not use D-Bus even if available.'
echo '  --disable-gnutls Do not use GNU TLS even if available.'
echo '  --disable-ipv6   Do not use IPv6 even if supported.'
echo '  --disable-nls    Disable NLS (native language support).'
echo '  --yacc=TOOL      Either "yacc" or "bison".'
echo '  --bindir=PATH    Directory used for installing executables.'
echo '  --datadir=PATH   Directory used for installing application data.'
echo '  --localedir=PATH Directory used for installing locale data.'
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

# Make sure previous Configure settings have no influence.
make clobber >/dev/null 2>&1 || : ignore failure

# Use /bin/sh explicitely so that it works on noexec mounted file systems.
# Note: Configure won't work as of yet on such a file system.
/bin/sh ./Configure -Oders \
	${build_bindir} \
	${build_cc} \
	${build_ccflags} \
	${build_datadir} \
	${build_dbus} \
	${build_gnutls} \
	${build_ipv6} \
	${build_ldflags} \
	${build_localedir} \
	${build_mandir} \
	${build_nls} \
	${build_official} \
	${build_prefix} \
	${build_ui} \
	${build_yacc} || { echo; echo 'ERROR: Configure failed.'; exit 1; }

make || { echo; echo 'ERROR: Compiling failed.'; exit 1; }

echo 'Run "make install" to install gtk-gnutella.'
exit

