: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.0 PL70]
: $X-Id: Jmake.tmpl 8 2006-08-25 22:27:18Z rmanfredi $

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
CURRENT=pixmaps
DIR=`echo $CURRENT/ | sed -e 's/\.\///g'`
echo "Extracting ${DIR}Makefile (with variable substitutions)"

INSTALL=`echo $install | sed -e 's,\./i,\$(TOP)/i,'`
INSTALLDIR=`echo $installdir | sed -e 's,\./i,\$(TOP)/i,'`
DATE=`date`

$spitshell >Makefile <<!GROK!THIS!
########################################################################
# Makefile generated from Makefile.SH on $DATE

SHELL = /bin/sh
JMAKE = jmake
TOP = ..
CURRENT = $CURRENT
DIR = $DIR
INSTALL = $INSTALL
INSTALLDIR = $INSTALLDIR

########################################################################
# Parameters set by Configure -- edit config.sh if changes are needed

CTAGS = ctags
JCPPFLAGS = $cppflags
MV = $mv
PRIVLIB = $installprivlib
RM = $rm -f

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules 8 2006-08-25 22:27:18Z rmanfredi $

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile 11129 2006-06-20 22:13:22Z cbiere $

PIXMAPS = \
	arrow_down.xpm \
	arrow_up.xpm \
	booklib.xpm \
	booksha.xpm \
	bookshav.xpm \
	booktth.xpm \
	booktthv.xpm \
	chip.xpm \
	clanbomber_red.xpm \
	clanbomber_yellow.xpm \
	download.xpm \
	exit.xpm \
	filter.xpm \
	firewall.xpm \
	firewall_punchable.xpm \
	firewall_tcp.xpm \
	firewall_udp.xpm \
	firewall_udp_punchable.xpm \
	freeze.xpm \
	icon.xpm \
	icon.16x16.xpm \
	icon.32x32.xpm \
	leaf.xpm \
	legacy.xpm \
	magnet.16x16.png \
	magnet.32x32.png \
	magnet.64x64.png \
	no_firewall.xpm \
	offline.xpm \
	online.xpm \
	save.xpm \
	smallserver.xpm \
	stock_form-time-field-16.xpm \
	thaw.xpm \
	ultra.xpm \
	upload.xpm \
	warning.xpm

all::

INSTALLFLAGS = -m 444

local_install:: $(PIXMAPS)
	@case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(PRIVLIB)/pixmaps || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$(PRIVLIB)/pixmaps); \
	for i in $(PIXMAPS); do \
		(set -x; $(INSTALL) -c $(INSTALLFLAGS) \
			$$i $(INSTALL_PREFIX)$(PRIVLIB)/pixmaps) || exit 1;\
	done

local_deinstall::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for i in $(PIXMAPS); do \
		(set -x; $(RM) $(INSTALL_PREFIX)$(PRIVLIB)/pixmaps/$$i); \
	done

########################################################################
# Common rules for all Makefiles -- do not edit

all::

clean: local_clean
realclean: local_realclean
clobber: local_clobber

local_clean::
	if test -f core; then $(RM) core; fi
	$(RM) *~ *.o

local_realclean:: local_clean

local_clobber:: local_realclean
	$(RM) Makefile config.sh

install:: local_install
install.man:: maybe_install.man
deinstall:: local_deinstall
deinstall.man:: maybe_deinstall.man

install.man-no:
deinstall.man-no:

maybe_install.man: install.man-no
maybe_deinstall.man: deinstall.man-no

Makefile.SH: Jmakefile
	-@if test -f $(TOP)/.package; then \
		if test -f Makefile.SH; then \
			echo "	$(RM) Makefile.SH~; $(MV) Makefile.SH Makefile.SH~"; \
			$(RM) Makefile.SH~; $(MV) Makefile.SH Makefile.SH~; \
		fi; \
		echo "	$(JMAKE) -DTOPDIR=$(TOP) -DCURDIR=$(CURRENT)" ; \
		$(JMAKE) -DTOPDIR=$(TOP) -DCURDIR=$(CURRENT) ; \
	else touch $@; fi

Makefile: Makefile.SH
	/bin/sh Makefile.SH

tags::
	$(CTAGS) -w *.[ch]
	$(CTAGS) -xw *.[ch] > tags

local_clobber::
	$(RM) tags

########################################################################
# Empty rules for directories with no sub-directories -- do not edit

local_install::
	@echo "install in $(CURRENT) done."

local_deinstall::
	@echo "deinstall in $(CURRENT) done."

local_install.man::
	@echo "install.man in $(CURRENT) done."

local_deinstall.man::
	@echo "deinstall.man in $(CURRENT) done."

Makefiles::

Makefiles.SH::

!NO!SUBS!
chmod 644 Makefile
$eunicefix Makefile

