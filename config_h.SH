case $CONFIG in
'')
	if test -f config.sh; then TOP=.;
	elif test -f ../config.sh; then TOP=..;
	elif test -f ../../config.sh; then TOP=../..;
	elif test -f ../../../config.sh; then TOP=../../..;
	elif test -f ../../../../config.sh; then TOP=../../../..;
	else
		echo "Can't find config.sh."; exit 1
	fi
	. $TOP/config.sh
	;;
esac
case "$0" in
*/*) cd `expr X$0 : 'X\(.*\)/'` ;;
esac
echo "Extracting config.h (with variable substitutions)"
sed <<!GROK!THIS! >config.h -e 's!^#undef\(.*/\)\*!/\*#define\1 \*!' -e 's!^#un-def!#undef!'
/*
 * This file was produced by running the config_h.SH script, which
 * gets its values from config.sh, which is generally produced by
 * running Configure.
 *
 * Feel free to modify any of this as the need arises.  Note, however,
 * that running config_h.SH again will wipe out any changes you've made.
 * For a more permanent change edit config.sh and rerun config_h.SH.
 *
 * \$Id$
 */

/*
 * Package name      : $package
 * Source directory  : $src
 * Configuration time: $cf_time
 * Configured by     : $cf_by
 * Target system     : $myuname
 */

#ifndef _config_h_
#define _config_h_

/* BSD:
 *	This symbol, if defined, indicates that the program is running under
 *	a BSD system.
 */
#$d_bsd BSD		/**/

/* CAT2:
 *	This macro catenates 2 tokens together.
 */
/* CAT3:
 *	This macro catenates 3 tokens together.
 */
/* STRINGIFY:
 *	This macro surrounds its token with double quotes.
 */
#if $cpp_stuff == 1
#define CAT2(a,b)a/**/b
#define CAT3(a,b,c)a/**/b/**/c
#define STRINGIFY(a)"a"
#define SQuoTe(a)"a
#define EQuoTe(a)a"
#endif
#if $cpp_stuff == 42
#define CAT2(a,b)a ## b
#define CAT3(a,b,c)a ## b ## c
#define StGiFy(a)# a
#define STRINGIFY(a)StGiFy(a)
#endif
#if $cpp_stuff != 1 && $cpp_stuff != 42
#include "Bletch: How does this C preprocessor catenate tokens?"
#endif

/* HASATTRIBUTE:
 *	This symbol indicates the C compiler can check for function attributes,
 *	such as printf formats. This is normally only supported by GNU cc.
 */
#$d_attribut HASATTRIBUTE 	/**/
#ifndef HASATTRIBUTE
#define __attribute__(_arg_)
#endif

/* HAS_BCOPY:
 *	This symbol is defined if the bcopy() routine is available to
 *	copy blocks of memory.
 */
#$d_bcopy HAS_BCOPY	/**/

/* HASCONST:
 *	This symbol, if defined, indicates that this C compiler knows about
 *	the const type. There is no need to actually test for that symbol
 *	within your programs. The mere use of the "const" keyword will
 *	trigger the necessary tests.
 */
#$d_const HASCONST	/**/
#ifndef HASCONST
#define const
#endif

/* HAS_INET_ATON:
 *	This symbol, if defined, indicates to the C program that the
 *	inet_aton() function is available to parse IP address "dotted-quad"
 *	strings.
 */
#$d_inetaton HAS_INET_ATON		/**/

/* HAS_ISASCII:
 *	This manifest constant lets the C program know that isascii 
 *	is available.
 */
#$d_isascii HAS_ISASCII		/**/

/* HAS_MEMCPY:
 *	This symbol, if defined, indicates that the memcpy routine is available
 *	to copy blocks of memory.
 */
#$d_memcpy HAS_MEMCPY	/**/

/* HAS_SOCKET:
 *	This symbol, if defined, indicates that the BSD socket interface is
 *	supported.
 */
#$d_socket HAS_SOCKET		/**/

/* HASVOLATILE:
 *	This symbol, if defined, indicates that this C compiler knows about
 *	the volatile declaration.
 */
#$d_volatile	HASVOLATILE	/**/
#ifndef HASVOLATILE
#define volatile
#endif

/* I_SYS_PARAM:
 *	This symbol, if defined, indicates to the C program that it should
 *	include <sys/param.h>.
 */
#$i_sysparam I_SYS_PARAM		/**/

/* PRIVLIB_EXP:
 *	This symbol contains the ~name expanded version of PRIVLIB, to be used
 *	in programs that are not prepared to deal with ~ expansion at run-time.
 */
#define PRIVLIB_EXP "$privlibexp"		/**/

/* VOIDFLAGS:
 *	This symbol indicates how much support of the void type is given by this
 *	compiler.  What various bits mean:
 *
 *	    1 = supports declaration of void
 *	    2 = supports arrays of pointers to functions returning void
 *	    4 = supports comparisons between pointers to void functions and
 *		    addresses of void functions
 *	    8 = suports declaration of generic void pointers
 *
 *	The package designer should define VOIDUSED to indicate the requirements
 *	of the package.  This can be done either by #defining VOIDUSED before
 *	including config.h, or by defining defvoidused in Myinit.U.  If the
 *	latter approach is taken, only those flags will be tested.  If the
 *	level of void support necessary is not present, defines void to int.
 */
#ifndef VOIDUSED
#define VOIDUSED $defvoidused
#endif
#define VOIDFLAGS $voidflags
#if (VOIDFLAGS & VOIDUSED) != VOIDUSED
#define void int		/* is void to be avoided? */
#define M_VOID			/* Xenix strikes again */
#endif

/* CAN_PROTOTYPE:
 *	If defined, this macro indicates that the C compiler can handle
 *	function prototypes.
 */
/* P:
 *	This macro is used to declare function parameters for folks who want
 *	to make declarations with prototypes using a different style than
 *	the above macros.  Use double parentheses.  For example:
 *
 *		int main P((int argc, char *argv[]));
 */
#$prototype	CAN_PROTOTYPE	/**/
#ifdef CAN_PROTOTYPE
#define	P(args) args
#else
#define	P(args) ()
#endif

/* HAS_BIND_TEXTDOMAIN_CODESET:
 *	This symbol, if defined, indicates that the bind_textdomain_codeset routine
 *	is available.
 */
#$d_bindtxtcode HAS_BIND_TEXTDOMAIN_CODESET		/**/

/* HAS_HERROR:
 *	This symbol, if defined, indicates that the herror routine is
 *	available.
 */
#$d_herror HAS_HERROR		/**/

/* HAS_HSTRERROR:
 *	This symbol, if defined, indicates that the hstrerror routine is
 *	available.
 */
#$d_hstrerror HAS_HSTRERROR		/**/

/* USE_IP_TOS:
 *	This symbol, if defined, indicates that the IP TOS services are
 *	available and can be used.  Be prepared to include <sys/socket.h>,
 * either <netinet/in.h> or <sys/in.h>, and <netinet/ip.h> when
 *	I_NETINET_IP is defined.
 */
#$d_iptos USE_IP_TOS		/**/

/* HAS_RANDOM:
 *	This symbol, if defined, indicates that the random routine is
 *	available.
 */
#$d_random HAS_RANDOM		/**/

/* HAS_SENDFILE:
 *	This symbol, if defined, indicates that the sendfile routine is
 *	available.
 */
#$d_sendfile HAS_SENDFILE		/**/

/* HAS_SRANDOM:
 *	This symbol, if defined, indicates that the srandom routine is
 *	available.
 */
#$d_srandom HAS_SRANDOM		/**/

/* HAS_STRCASESTR:
 *	This symbol, if defined, indicates that the strcasestr routine is
 *	available.
 */
#$d_strcasestr HAS_STRCASESTR		/**/

/* HAS_STRLCPY:
 *	This symbol, if defined, indicates that the chown routine is
 *	available.
 */
#$d_strlcpy HAS_STRLCPY		/**/

/* HAS_SYSCTL:
 *	This symbol, if defined, indicates that the sysctl routine is
 *	available.
 */
#$d_sysctl HAS_SYSCTL		/**/

/* HAS_VSNPRINTF:
 *	This symbol, if defined, indicates that the vsnprintf routine is
 *	available.
 */
#$d_vsnprintf HAS_VSNPRINTF		/**/

/* I_LANGINFO:
 *	This symbol, if defined, indicates to the C program that it should
 *	include <langinfo.h>.
 */
#$i_langinfo I_LANGINFO		/**/

/* I_LIBCHARSET:
 *	This symbol, if defined, indicates to the C program that it should
 *	include <libcharset.h>.
 */
#$i_libcharset I_LIBCHARSET		/**/

/* I_NETINET_IP:
 *	This symbol, if defined, indicates to the C program that it should
 *	include <netinet/ip.h>.
 */
#$i_niip I_NETINET_IP	/**/

/* I_SYS_SENDFILE:
 *	This symbol, if defined, indicates to the C program that it should
 *	include <sys/sendfile.h>.
 */
#$i_syssendfile I_SYS_SENDFILE		/**/

/* I_SYS_SYSCTL:
 *	This symbol, if defined, indicates to the C program that it should
 *	include <sys/sysctl.h>.
 */
#$i_syssysctl I_SYS_SYSCTL		/**/

/* OFFICIAL_BUILD:
 * When defined, the build is "official".  Programs generated for an
 *	official build MUST NOT peek into the place where the sources lie, via
 *	PACKAGE_SOURCE_DIR or any other means.
 */
#$d_official OFFICIAL_BUILD	/**/

/* PACKAGE_SOURCE_DIR:
 * Holds the directory name holding the package source.
 */
#define PACKAGE_SOURCE_DIR "$pkgsrc"

/* USE_GTK1:
 * This symbol is defined when compiling for the GTK1 toolkit.
 */
/* USE_GTK2:
 * This symbol is defined when compiling for the GTK2 toolkit.
 */
#$d_usegtk1 USE_GTK1    /**/
#$d_usegtk2 USE_GTK2    /**/

/* USE_REMOTE_CTRL:
 * This symbol is defined when they want remote control support.
 */
#$d_remotectrl USE_REMOTE_CTRL    /**/

/* HAS_LIBXML2:
 * This symbol is defined when libxml 2.4.19, at least, is present.
 */
#$d_libxml2 HAS_LIBXML2	/**/

#endif
!GROK!THIS!
