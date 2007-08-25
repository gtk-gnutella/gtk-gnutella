#! /bin/sh

# This is a simple wrapper script to make compiling a bit easier.
# Configure is too verbose and curious about many things and not
# sufficiently eloquent about others such as available options.

# Bail out on unexpected errors
set -e

# This is not interactive
exec </dev/null

build_bindir=
build_configure_only=
build_datadir=
build_dbus=
build_gnutls=
build_halloc=
build_ipv6=
build_localedir=
build_nls=
build_official=
build_so_suffix=
build_socker=
build_ui=

while [ $# -gt 0 ]; do
	case "$1" in
	--bindir=*)		build_bindir="${1#--*=}";;
	--cc=*)			CC="${1#--*=}";;
	--cflags=*)		CFLAGS="${1#--*=}";;
	--configure-only)	build_configure_only='yes';;
	--datadir=*)		build_datadir="${1#--*=}";;
	--disable-dbus)		build_dbus='d_dbus';;
	--disable-gnutls)	build_gnutls='d_gnutls';;
	--disable-ipv6)		build_ipv6='d_ipv6';;
	--disable-nls)		build_nls='d_enablenls';;
	--disable-socker)	build_socker='d_socker_get';;
	--enable-halloc)	build_halloc='true';;
	--gtk1)			build_ui='gtkversion=1';;
	--gtk2)			build_ui='gtkversion=2';;
	--ldflags=*)		LDFLAGS="${1#--*=}";;
	--localedir=*)		build_localedir="${1#--*=}";;
	--mandir=*)		build_mandir="${1#--*=}";;
	--make=*)		MAKE="${1#--*=}";;
	--prefix=*)		PREFIX="${1#--*=}";;
	--topless)		build_ui='d_headless';;
	--unofficial)		build_official='false';;
	--yacc=*)		YACC="${1#--*=}";;
	--) 		break
			;;
	*)
echo 'The following switches are available, defaults are shown in brackets:'
echo
echo '  --gtk2           Use Gtk+ 2.x for the user interface [default].'
echo '  --gtk1           Use the deprecated Gtk+ 1.2 for the user interface.'
echo '  --topless        Compile for topless use (no graphical user interface).'
echo '  --disable-dbus   Do not use D-Bus even if available.'
echo '  --disable-gnutls Do not use GNU TLS even if available.'
echo '  --disable-ipv6   Do not use IPv6 even if supported.'
echo '  --disable-nls    Disable NLS (native language support).'
echo '  --disable-socker Disable support for Socker.'
echo '  --prefix=PATH    Path prefix used for installing files. [$PREFIX]'
echo '  --bindir=PATH    Directory for installing executables. [$PREFIX/bin]'
echo '  --datadir=PATH   Directory for installing application data. [$PREFIX/share]'
echo '  --localedir=PATH Directory for installing locale data. [$PREFIX/share/locale]'
echo '  --mandir=PATH    Directory for installing manual pages. [$PREFIX/man]'
echo '  --cc=TOOL        C compiler to use. [$CC]'
echo '  --cflags=FLAGS   Flags to pass to the C compiler. [$CFLAGS]'
echo '  --ldflags=FLAGS  Flags to pass to the linker. [$LDFLAGS]'
echo '  --make=TOOL      make tool to be used. [$MAKE]'
echo '  --yacc=TOOL      yacc, bison or some compatible tool. [$YACC]'
echo '  --configure-only Do not run make after Configure.'
echo '  --unofficial     Use for test builds only. Requires no installation.'
echo '  --enable-halloc  Enable mmap()-based malloc() replacement.'
echo
echo 'Typically no switches need to be used. Just run '"$0"' to start the'
echo 'build process.'
			case "$1" in
			--help);;
			*) 	echo
				echo "ERROR: Unknown switch: \"$1\"";;
		esac
		exit 1
		;;
	esac
	shift
done

if [ "X$MAKE" = X ]; then
	command -v gmake >/dev/null 2>&1 && MAKE=gmake || MAKE=make
fi

if [ "X$YACC" = X ]; then
	command -v yacc >/dev/null 2>&1 && YACC=yacc || YACC=bison
fi

CFLAGS="$CFLAGS${build_halloc:+ -DUSE_HALLOC}"
PREFIX=${PREFIX:-/usr/local}

build_bindir=${build_bindir:-$PREFIX/bin}
build_bindir=${build_bindir:+"$build_bindir"}

build_mandir=${build_mandir:-$PREFIX/man}
build_mandir=${build_mandir:+"$build_mandir"}

build_datadir=${build_datadir:-$PREFIX/share/gtk-gnutella}
build_datadir=${build_datadir:+"$build_datadir"}

build_localedir=${build_localedir:-$PREFIX/share/locale}
build_localedir=${build_localedir:+"$build_localedir"}

build_official=${build_official:-true}
build_ui=${build_ui:-gtkversion=2}

# There is something broken about Configure, so it needs to know the
# suffix for shared objects (dynamically loaded libraries) for some odd
# reasons.
case "`uname -s`" in
darwin|Darwin) build_so_suffix='dylib';;
esac

# Make sure previous Configure settings have no influence.
${MAKE} clobber >/dev/null 2>&1 || : ignore failure
rm -f config.sh

# Use /bin/sh explicitely so that it works on noexec mounted file systems.
# Note: Configure won't work as of yet on such a file system.
/bin/sh ./Configure -Oders \
	-U usenm \
	${CC:+-D "cc=$CC"} \
	${CFLAGS:+-D "ccflags=$CFLAGS"} \
	${LDFLAGS:+-D "ldflags=$LDFLAGS"} \
	${PREFIX:+-D "prefix=$PREFIX"} \
	${MAKE:+-D "make=$MAKE"} \
	${YACC:+-D "yacc=$YACC"} \
	${build_bindir:+-D "bindir=$build_bindir"} \
	${build_datadir:+-D "privlib=$build_datadir"} \
	${build_localedir:+-D "locale=$build_localedir"} \
	${build_mandir:+-D "sysman=$build_mandir"} \
	${build_official:+-D "official=$build_official"} \
	${build_so_suffix:+-D "so=$build_so_suffix"} \
	${build_ui:+-D "$build_ui"} \
	${build_nls:+-U "$build_nls"} \
	${build_dbus:+-U "$build_dbus"} \
	${build_gnutls:+-U "$build_gnutls"} \
	${build_ipv6:+-U "$build_ipv6"} \
	${build_socker:+-U "$build_socker"} \
	|| { echo; echo 'ERROR: Configure failed.'; exit 1; }

if [ "X$build_configure_only" != X ]; then
	exit
fi

${MAKE} || { echo; echo 'ERROR: Compiling failed.'; exit 1; }

echo "Run \"${MAKE} install\" to install gtk-gnutella."
exit

