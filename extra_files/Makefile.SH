: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-224]
: $X-Id$

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
JCPPFLAGS = $cppflags
MV = $mv
PRIVLIB = $installprivlib
RM = $rm -f

########################################################################
# Automatically generated parameters -- do not edit

SUBDIRS = el en it fr ja tr

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id$

########################################################################
# Start of Jmakefile

# $X-Id$

all::

EXTRA_FILES = \
	bogons.txt \
	favicon.png \
	geo-ip.txt \
	geo-ipv6.txt \
	gwcache.boot \
	hostiles.txt \
	robots.txt \
	spam.txt \
	spam_sha1.txt

PIXMAP_FILES = \
	gtk-gnutella.png	\
	gtk-gnutella.svg

DESKTOP_FILES = \
	gtk-gnutella.desktop

APPDATA_FILES = \
	gtk-gnutella.appdata.xml

INSTALLFLAGS = -m 444

local_install local_install-strip::
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

local_install:: $(APPDATA_FILES)
	@case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/appdata || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/appdata); \
	for i in $(APPDATA_FILES); do \
		(set -x; $(INSTALL) -c $(INSTALLFLAGS) \
			$$i $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/appdata) || exit 1;\
	done

local_deinstall::
	@case '${MFLAGS}' in *[i]*) set +e;; esac; \
	for i in $(APPDATA_FILES); do \
		(set -x; $(RM) $(INSTALL_PREFIX)$(INSTALLPREFIX)/share/appdata/$$i); \
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

update: update_bogons update_geoip update_geoipv6

update_bogons:
# Target disabled, site seems to be down definitively? -- RAM, 2009-01-16
	: wget http://www.completewhois.com/bogons/data/bogons-cidr-all.txt \
		-O bogons.txt

update_geoip:
	rm -f GeoIPCountryCSV.zip
	wget http://www.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip
	rm -f GeoIPCountryWhois.csv
	unzip GeoIPCountryCSV.zip
	$(TOP)/scripts/geo-to-db.pl -c GeoIPCountryWhois.csv >geo-ip.txt

update_geoipv6:
	rm -f GeoIPv6.csv.gz
	wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.csv.gz
	rm -f GeoIPv6.csv
	gunzip GeoIPv6.csv.gz
	$(TOP)/scripts/geo6-to-db.pl -g GeoIPv6.csv >geo-ipv6.txt

########################################################################
# Common rules for all Makefiles -- do not edit

all::

clean: sub_clean local_clean
realclean: sub_realclean local_realclean
clobber: sub_clobber local_clobber

local_clean::
	if test -f core; then $(RM) core; fi
	$(RM) *~ *.o

local_realclean:: local_clean

local_clobber:: local_realclean
	$(RM) Makefile config.sh

install:: local_install sub_install
	@exit 0

install-strip:: local_install-strip sub_install-strip
	@exit 0

install.man:: maybe_install.man sub_install.man
deinstall:: sub_deinstall local_deinstall
deinstall.man:: sub_deinstall.man maybe_deinstall.man

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
# Rules for building in sub-directories -- do not edit

subdirs:
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "$(VERB) in $(DIR)$$i..."; \
			$(MAKE) $(MFLAGS) $(FLAGS) $(TARGET)) || exit 1; \
	done

sub_install::
	@$(MAKE) subdirs TARGET=install VERB="Installing" FLAGS=

sub_install-strip::
	@$(MAKE) subdirs TARGET=install-strip VERB="Installing (strip)" FLAGS=

sub_deinstall::
	@$(MAKE) subdirs TARGET=deinstall VERB="Deinstalling" FLAGS=
	@echo "Back to $(CURRENT) for "deinstall...

sub_install.man::
	@$(MAKE) subdirs TARGET=install.man VERB="Installing man pages" FLAGS=

sub_deinstall.man::
	@$(MAKE) subdirs TARGET=deinstall.man VERB="Deinstalling man pages" FLAGS=
	@echo "Back to $(CURRENT) for "deinstall.man...

sub_clean::
	@$(MAKE) subdirs TARGET=clean VERB="Cleaning" FLAGS=
	@echo "Back to $(CURRENT) for "clean...

sub_realclean::
	@$(MAKE) subdirs TARGET=realclean VERB="Real cleaning" FLAGS=
	@echo "Back to $(CURRENT) for "realclean...

sub_clobber::
	@$(MAKE) subdirs TARGET=clobber VERB="Clobbering" FLAGS=
	@echo "Back to $(CURRENT) for "clobber...

tag::
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "Tagging" "in $(DIR)$$i..."; \
			$(MAKE) $(MFLAGS)  tag) || exit 1; \
	done

Makefiles::
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS);\
	do \
		echo "Making "Makefiles" in $(DIR)$$i..."; \
		(cd $$i || exit 1; \
		if test ! -f Makefile; then /bin/sh Makefile.SH; fi; \
		$(MAKE) $(MFLAGS) Makefiles) || exit 1;\
	done

Makefiles.SH:: Makefile.SH
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS);\
	do \
		case "$(DIR)$$i/" in \
		*/*/*/*/) newtop=../../../..;; \
		*/*/*/) newtop=../../..;; \
		*/*/) newtop=../..;; \
		*/) newtop=..;; \
		esac; \
		case "$(TOP)" in \
		/*) newtop="$(TOP)" ;; \
		esac; \
		echo "Making Makefiles.SH in $(DIR)$$i..."; \
		(cd $$i || exit 1; \
			if test -f Jmakefile; then \
				$(MAKE) $(MFLAGS) -f ../Makefile \
					Makefile TOP=$$newtop CURRENT=$(DIR)$$i && \
				$(MAKE) $(MFLAGS) Makefiles.SH; \
			fi; \
		) || exit 1; \
	done

all::
	@$(MAKE) subdirs TARGET=all VERB="Making all" FLAGS=

local_install::
local_install-strip::
local_deinstall::
local_install.man::
local_deinstall.man::

!NO!SUBS!
chmod 644 Makefile
$eunicefix Makefile

