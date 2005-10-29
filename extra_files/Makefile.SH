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
CURRENT=extra_files
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
INSTALLPREFIX = $prefix
MV = $mv
PRIVLIB = $installprivlib
RM = $rm -f

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules,v 3.0.1.7 2004/08/22 08:28:58 ram Exp ram $

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile,v 1.1 2005/10/26 08:28:52 rmanfredi Exp $

EXTRA_FILES = \
	bogons.txt \
	favicon.png \
	gwcache.boot \
	geo-ip.txt \
	hostiles.txt \
	robots.txt

PIXMAP_FILES = \
	gtk-gnutella.png	\
	gtk-gnutella.svg

DESKTOP_FILES = \
	gtk-gnutella.desktop

INSTALLFLAGS = -m 444

local_install::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for dir in $(PRIVLIB); do	\
		(set -x; test -d $(INSTALL_PREFIX)$$dir || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$$dir);	\
	done

local_deinstall::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for dir in $(PRIVLIB); do \
		(set -x; test -d $$dir && $(RM) -r $(INSTALL_PREFIX)$$dir); \
	done

local_install:: $(EXTRA_FILES)
	@case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(PRIVLIB) || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$(PRIVLIB)); \
	for i in $(EXTRA_FILES); do \
		(set -x; $(INSTALL) -c $(INSTALLFLAGS) \
			$$i $(INSTALL_PREFIX)$(PRIVLIB)) || exit 1;\
	done

local_deinstall::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for i in $(EXTRA_FILES); do \
		(set -x; $(RM) $(INSTALL_PREFIX)$(PRIVLIB)/$$i); \
	done

local_install:: $(DESKTOP_FILES)
	@case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/applications || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/applications); \
	for i in $(DESKTOP_FILES); do \
		(set -x; $(INSTALL) -c $(INSTALLFLAGS) \
			$$i $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/applications) || exit 1;\
	done

local_deinstall::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for i in $(DESKTOP_FILES); do \
		(set -x; $(RM) $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/applications/$$i); \
	done

local_install:: $(PIXMAP_FILES)
	@case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/pixmaps || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/pixmaps); \
	for i in $(PIXMAP_FILES); do \
		(set -x; $(INSTALL) -c $(INSTALLFLAGS) \
			$$i $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/pixmaps) || exit 1;\
	done

local_deinstall::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for i in $(PIXMAP_FILES); do \
		(set -x; $(RM) $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/pixmaps/$$i); \
	done

#
# Update the bogons and GeoIp databases
#

update:
	wget http://www.completewhois.com/bogons/data/bogons-cidr-all.txt \
		-O bogons.txt
	rm -f GeoIPCountryCSV.zip
	wget http://www.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip
	rm -f GeoIPCountryWhois.csv
	unzip GeoIPCountryCSV.zip
	$(TOP)/scripts/geo-to-db.pl -c GeoIPCountryWhois.csv >geo-ip.txt

########################################################################
# Common rules for all Makefiles -- do not edit

emptyrule::

clean: local_clean
realclean: local_realclean
clobber: local_clobber

local_clean::
	if test -f core; then $(RM) core; fi
	$(RM) *~ *.o

local_realclean:: local_clean

local_clobber:: local_realclean
	$(RM) Makefile config.sh

install: local_install
install.man: maybe_install.man
deinstall: local_deinstall
deinstall.man: maybe_deinstall.man

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

all:

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

