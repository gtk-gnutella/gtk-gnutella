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
CURRENT=.
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
TOP = .
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

########################################################################
# Automatically generated parameters -- do not edit

SUBDIRS = src pixmaps po

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules,v 3.0.1.7 2004/08/22 08:28:58 ram Exp ram $

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile,v 1.16 2005/09/11 08:18:50 rmanfredi Exp $

EXTRA_FILES = \
	extra_files/bogons.txt \
	extra_files/favicon.png \
	extra_files/gwcache.boot \
	extra_files/geo-ip.txt \
	extra_files/hostiles.txt \
	extra_files/robots.txt

PIXMAP_FILES = \
	extra_files/gtk-gnutella.png	\
	extra_files/gtk-gnutella.svg

DESKTOP_FILES = \
	extra_files/gtk-gnutella.desktop

all::

depend::
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in src ;\
	do \
		(cd $$i ; echo "Depending" "in $(DIR)$$i..."; \
			$(MAKE) $(MFLAGS)  depend) || exit 1; \
	done

local_clobber::
	$(RM) install gtk-gnutella.spec

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
	./geo-to-db.pl -c GeoIPCountryWhois.csv >geo-ip.txt

########################################################################
# Common rules for all Makefiles -- do not edit

emptyrule::

clean: sub_clean local_clean
realclean: sub_realclean local_realclean
clobber: sub_clobber local_clobber

local_clean::
	if test -f core; then $(RM) core; fi
	$(RM) *~ *.o

local_realclean:: local_clean
	$(RM) -r UU

local_clobber:: local_realclean
	$(RM) config.sh config.h
	$(RM) -r .config
	$(RM) Makefile

install: local_install sub_install
install.man: maybe_install.man sub_install.man
deinstall: sub_deinstall local_deinstall
deinstall.man: sub_deinstall.man maybe_deinstall.man

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
# Rules for building in sub-directories -- do not edit

subdirs:
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo $(VERB) "in $(DIR)$$i..."; \
			$(MAKE) $(MFLAGS) $(FLAGS) $(TARGET)) || exit 1; \
	done

sub_install::
	@$(MAKE) subdirs TARGET=install VERB="Installing" FLAGS=

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
local_deinstall::
local_install.man::
local_deinstall.man::

!NO!SUBS!
chmod 644 Makefile
$eunicefix Makefile

