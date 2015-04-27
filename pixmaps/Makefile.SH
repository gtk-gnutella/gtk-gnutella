: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-195]
: $X-Id: Jmake.tmpl 183 2015-04-12 09:48:11Z rmanfredi $

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
# $X-Id: Jmake.rules 195 2015-04-27 21:30:17Z rmanfredi $

########################################################################
# Start of Jmakefile

# $X-Id$

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
	go_back.xpm \
	hungup.xpm \
	icon.16x16.xpm \
	icon.48x48.xpm \
	icon.xpm \
	leaf.xpm \
	legacy.xpm \
	magnet.16x16.png \
	magnet.32x32.png \
	magnet.64x64.png \
	natpmp.xpm \
	no_firewall.xpm \
	offline.xpm \
	online.xpm \
	pause.xpm \
	save.xpm \
	smallserver.xpm \
	star-black.xpm \
	star-blue.xpm \
	star-green.xpm \
	star-red.xpm \
	star-violet.xpm \
	star-yellow.xpm \
	stock_form-time-field-16.xpm \
	thaw.xpm \
	ultra.xpm \
	upload-red.xpm \
	upload-yellow.xpm \
	upload.xpm \
	upnp-unusable.xpm \
	upnp.xpm \
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
	@exit 0

install-strip:: local_install-strip
	@exit 0

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

depend::

########################################################################
# Empty rules for directories with no sub-directories -- do not edit

local_install::
	@echo "install in $(CURRENT) done."

local_install-strip::
	@echo "install (strip) in $(CURRENT) done."

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

