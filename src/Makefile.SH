: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5 PL0]
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
CURRENT=src
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

BINDIR = $installbin
CC = $cc
CTAGS = ctags
_EXE = $_exe
JCFLAGS = \$(CFLAGS) $optimize $ccflags $large
JCPPFLAGS = $cppflags
JLDFLAGS = \$(LDFLAGS) $optimize $ldflags
L = $manext
LIBS = $libs
MANSRC = $installmansrc
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RM = $rm -f
SED = $sed

########################################################################
# Automatically generated parameters -- do not edit

SUBDIRS = core shell dht lib ui if
USRINC = $usrinc
SOURCES =   \$(SRC)
SOCKER_CFLAGS =  $sockercflags
GTK_CFLAGS =  $gtkcflags
GNUTLS_LDFLAGS =  $gnutlsldflags
GNUTLS_CFLAGS =  $gnutlscflags
DBUS_LDFLAGS =  $dbusldflags
XML2_LDFLAGS =  $xmlldflags
GTK_LDFLAGS =  $gtkldflags
OBJECTS =   \$(OBJ) \$(EXTRA)
SOCKER_LDFLAGS =  $sockerldflags
DBUS_CFLAGS =  $dbuscflags
XML2_CFLAGS =  $xmlcflags

########################################################################
# New suffixes and associated building rules -- edit with care

.c.o:
	\$(CC) -c \$(JCFLAGS) \$<

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules 8 2006-08-25 22:27:18Z rmanfredi $

########################################################################
# Force 'make depend' to be performed first -- do not edit

.FORCE_DEPEND::

all:: .FORCE_DEPEND

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile 14436 2007-08-13 10:29:02Z rmanfredi $

all::

depend::
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "Depending" "in $(DIR)$$i..."; \
			$(MAKE) $(MFLAGS)  depend) || exit 1; \
	done

SRC = main.c
OBJ = main.o

EXTRA = \
	if/bridge/ui2c.o \
	if/bridge/c2ui.o \
	if/gnet_property.o \
	if/gui_property.o

CFLAGS = -I.. -I. \
	$(GTK_CFLAGS) \
	$(XML2_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GNUTLS_CFLAGS) \
	$(SOCKER_CFLAGS) \
	-DCURDIR=$(CURRENT)

DPFLAGS = $(CFLAGS)
LDFLAGS = \
	-Lshell -lshell \
	-Lcore -lcore \
	-Ldht -ldht \
!NO!SUBS!
case "$d_headless" in
undef)
	$spitshell >>Makefile <<'!NO!SUBS!'
	-Lui/gtk -lgtk-common -lgtkx -lgtk-common \
!NO!SUBS!
	;;
esac
$spitshell >>Makefile <<'!NO!SUBS!'
	-ldht -lcore -Llib -lshared \
	$(GTK_LDFLAGS) $(XML2_LDFLAGS) $(DBUS_LDFLAGS) $(GNUTLS_LDFLAGS) \
	$(SOCKER_LDFLAGS)

.FORCE:

lib/libshared.a: .FORCE
	@echo "Checking "libshared.a" in "lib"..."
	cd lib; $(MAKE) libshared.a
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  lib/libshared.a

core/libcore.a: .FORCE
	@echo "Checking "libcore.a" in "core"..."
	cd core; $(MAKE) libcore.a
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  core/libcore.a

shell/libshell.a: .FORCE
	@echo "Checking "libshell.a" in "shell"..."
	cd shell; $(MAKE) libshell.a
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  shell/libshell.a

dht/libdht.a: .FORCE
	@echo "Checking "libdht.a" in "dht"..."
	cd dht; $(MAKE) libdht.a
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  dht/libdht.a
!NO!SUBS!
case "$d_headless" in
undef)
	$spitshell >>Makefile <<'!NO!SUBS!'

ui/gtk/libgtk-common.a: .FORCE
	@echo "Checking "libgtk-common.a" in "ui/gtk"..."
	cd ui/gtk; $(MAKE) libgtk-common.a
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  ui/gtk/libgtk-common.a

ui/gtk/libgtkx.a: .FORCE
	@echo "Checking "libgtkx.a" in "ui/gtk"..."
	cd ui/gtk; $(MAKE) libgtkx.a
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  ui/gtk/libgtkx.a
!NO!SUBS!
	;;
esac
$spitshell >>Makefile <<'!NO!SUBS!'

if/bridge/ui2c.o: .FORCE
	@echo "Checking "ui2c.o" in "if/bridge"..."
	cd if/bridge; $(MAKE) ui2c.o
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  if/bridge/ui2c.o

if/bridge/c2ui.o: .FORCE
	@echo "Checking "c2ui.o" in "if/bridge"..."
	cd if/bridge; $(MAKE) c2ui.o
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  if/bridge/c2ui.o

if/gnet_property.o: .FORCE
	@echo "Checking "gnet_property.o" in "if"..."
	cd if; $(MAKE) gnet_property.o
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  if/gnet_property.o

if/gui_property.o: .FORCE
	@echo "Checking "gui_property.o" in "if"..."
	cd if; $(MAKE) gui_property.o
	@echo "Continuing in $(CURRENT)..."

gtk-gnutella:  if/gui_property.o

if/gnet_property.h: .FORCE
	@echo "Checking "gnet_property.h" in "if"..."
	cd if; $(MAKE) gnet_property.h
	@echo "Continuing in $(CURRENT)..."

main.o:  if/gnet_property.h

if/gui_property.h: .FORCE
	@echo "Checking "gui_property.h" in "if"..."
	cd if; $(MAKE) gui_property.h
	@echo "Continuing in $(CURRENT)..."

main.o:  if/gui_property.h

depend:: ../mkdep

../mkdep:
	@echo "You have to run Configure in $(TOP) first."; exit 1

depend::
	($(SED) '/^# DO NOT DELETE/q' Makefile && \
	$(MKDEP) $(SOURCES) | \
	$(SED) -e 's:/usr/lib[^ ]*::g; s:$(USRINC)[^ ]*::g; ' \
		-e '/: / b print' -e '$$ b print' -e 'H; d; n; : print' \
		-e 'x; s/\\$$//; s/\\\n//g; s/  */ /g; s/ :/:/;' -e '/: *$$/d' \
	) > Makefile.new
	cp Makefile Makefile.bak
	cp Makefile.new Makefile
	$(RM) Makefile.new

all:: gtk-gnutella

local_realclean::
	$(RM) gtk-gnutella

gtk-gnutella:  $(OBJ) $(EXTRA)
	$(RM) $@
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@  $(OBJ) $(EXTRA) $(JLDFLAGS) $(LIBS)

local_install:: gtk-gnutella
	@case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(BINDIR) || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$(BINDIR)); \
	$(INSTALL) -c -m 555  gtk-gnutella$(_EXE) $(INSTALL_PREFIX)$(BINDIR)

local_deinstall::
	$(RM) $(INSTALL_PREFIX)$(BINDIR)/gtk-gnutella$(_EXE)

local_install.man:: gtk-gnutella.man
	@case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(MANSRC) || \
		$(INSTALLDIR) $(INSTALL_PREFIX)$(MANSRC)); \
	$(INSTALL) -c -m 444 gtk-gnutella.man $(INSTALL_PREFIX)$(MANSRC)/gtk-gnutella.$(L)

local_deinstall.man::
	$(RM) $(INSTALL_PREFIX)$(MANSRC)/gtk-gnutella.$(L)

main.o: revision.h

revision.h: .FORCE
	$(TOP)/scripts/svn-revision $(TOP) $@

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
install.man:: maybe_install.man sub_install.man
deinstall:: sub_deinstall local_deinstall
deinstall.man:: sub_deinstall.man maybe_deinstall.man

install.man-yes: local_install.man
install.man-no:
deinstall.man-yes: local_deinstall.man
deinstall.man-no:

!NO!SUBS!
case "$installmansrc" in
'') man=no;;
*) man=yes;;
esac
$spitshell >>Makefile <<!GROK!THIS!
maybe_install.man: install.man-$man
maybe_deinstall.man: deinstall.man-$man
!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'

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

########################################################################
# Dependencies generated by make depend
# DO NOT DELETE THIS LINE -- make depend relies on it

# Put nothing here or make depend will gobble it up
.FORCE_DEPEND::
	@echo "You must run 'make depend' in $(TOP) first."; exit 1
!NO!SUBS!
chmod 644 Makefile
$eunicefix Makefile

