: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.0 PL70]
: $X-Id: Jmake.tmpl,v 3.0.1.3 1997/02/28 14:56:16 ram Exp ram $

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
MAKE = make
MV = $mv
PRIVLIB = $installprivlib
RM = $rm -f

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules,v 3.0.1.6 1997/02/28 14:56:01 ram Exp ram $

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile,v 1.2 2003/08/09 22:38:30 rmanfredi Exp $

PIXMAPS = \
	arrow_down.xpm \
	arrow_up.xpm \
	booklib.xpm \
	booksha.xpm \
	bookshav.xpm \
	download.xpm \
	exit.xpm \
	filter.xpm \
	firewall.xpm \
	freeze.xpm \
	icon.xpm \
	leaf.xpm \
	legacy.xpm \
	no_firewall.xpm \
	offline.xpm \
	online.xpm \
	save.xpm \
	smallserver.xpm \
	thaw.xpm \
	ultra.xpm \
	upload.xpm

all::

local_install::
	@for dir in $(PRIVLIB)/pixmaps; do \
	case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$$dir			\
	|| $(INSTALLDIR) $(INSTALL_PREFIX)$$dir);	\
	done

local_deinstall::
	@for dir in $(PRIVLIB)/pixmaps; do \
	case '${MFLAGS}' in *[i]*) set +e;; esac; \
	(set -x; test -d $$dir && $(RM) -r $(INSTALL_PREFIX)$$dir); \
	done

local_install:: $(PIXMAPS)
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for i in $(PIXMAPS); do \
	(set -x; $(INSTALL) -c $(INSTALLFLAGS) $$i $(INSTALL_PREFIX)$(PRIVLIB)/pixmaps); \
	done

local_deinstall::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for i in $(PIXMAPS); do \
	(set -x; $(RM) $(INSTALL_PREFIX)$(PRIVLIB)/pixmaps/$$i); \
	done

########################################################################
# Common rules for all Makefiles -- do not edit

emptyrule::

clean: local_clean
realclean: local_realclean
clobber: local_clobber

local_clean::
	$(RM) core *~ *.o

local_realclean:: local_clean

local_clobber:: local_realclean
	$(RM) Makefile config.sh

install: local_install
install.man: local_install.man
deinstall: local_deinstall
deinstall.man: local_deinstall.man

Makefile.SH: Jmakefile
	-@if test -f $(TOP)/.package; then \
	if test -f Makefile.SH; then \
	echo "	$(RM) Makefile.SH~; $(MV) Makefile.SH Makefile.SH~"; \
	$(RM) Makefile.SH~; $(MV) Makefile.SH Makefile.SH~; \
	fi; \
	echo "	$(JMAKE) -DTOPDIR=$(TOP) -DCURDIR=$(CURRENT)" ; \
	$(JMAKE) -DTOPDIR=$(TOP) -DCURDIR=$(CURRENT) ; \
	else touch $@; exit 0; fi

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

