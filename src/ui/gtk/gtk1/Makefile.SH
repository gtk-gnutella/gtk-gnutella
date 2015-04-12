: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-183]
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
CURRENT=src/ui/gtk/gtk1
DIR=`echo $CURRENT/ | sed -e 's/\.\///g'`
echo "Extracting ${DIR}Makefile (with variable substitutions)"

DATE=`date`

$spitshell >Makefile <<!GROK!THIS!
########################################################################
# Makefile generated from Makefile.SH on $DATE

SHELL = /bin/sh
JMAKE = jmake
TOP = ../../../..
CURRENT = $CURRENT
DIR = $DIR

########################################################################
# Parameters set by Configure -- edit config.sh if changes are needed

AR = ar rc
CC = $cc
CP = $cp
CTAGS = ctags
JCFLAGS = \$(CFLAGS) $optimize $pthread $ccflags $large
JCPPFLAGS = $cppflags
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RANLIB = $ranlib
RM = $rm -f
SED = $sed

########################################################################
# Automatically generated parameters -- do not edit

USRINC = $usrinc
GLADE =  $glade
GTK_LDFLAGS =  $gtkldflags
SOURCES =   \$(SRC)
OBJECTS =   \$(OBJ)
GTK_CFLAGS =  $gtkcflags

########################################################################
# New suffixes and associated building rules -- edit with care

.c.o:
	\$(RM) \$@
	\$(CC) -c \$(JCFLAGS) \$<

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules 183 2015-04-12 09:48:11Z rmanfredi $

########################################################################
# Force 'make depend' to be performed first -- do not edit

all:: .FORCE_DEPEND

.FORCE_DEPEND::

########################################################################
# Start of Jmakefile

# $X-Id$

# Those files lie in the ../gtk-shared directory
REMOTE_GLADE_C = callbacks.c
REMOTE_GLADE_H = callbacks.h
REMOTE_GLADE = $(REMOTE_GLADE_C) $(REMOTE_GLADE_H)

LSRC = \
	fileinfo.c \
	gnet_stats.c \
	hcache.c \
	interface-glade.c \
	monitor_cb.c \
	monitor.c \
	nodes_cb.c \
	nodes.c \
	search_cb.c \
	search.c \
	search_stats.c \
	support-glade.c \
	upload_stats.c \
	uploads.c

LOBJ = \
	fileinfo.o \
	gnet_stats.o \
	hcache.o \
	interface-glade.o \
	monitor_cb.o \
	monitor.o \
	nodes_cb.o \
	nodes.o \
	search_cb.o \
	search.o \
	search_stats.o \
	support-glade.o \
	upload_stats.o \
	uploads.o \
	callbacks.o 

GLADE_C = \
	interface-glade.c \
	support-glade.c

GLADE_H = \
	interface-glade.h \
	support-glade.h 

GLADE_O = \
	interface-glade.o \
	support-glade.o \
	callbacks.o 

GLADE_GEN = $(GLADE_C) $(GLADE_H)

SRC = $(LSRC) $(GLADE_C) $(REMOTE_GLADE_C)
OBJ = $(LOBJ) $(GLADE_O)

TOP_SRC = ../../..
TOP_GUI = ../..

# Those extra flags are expected to be user-defined
CFLAGS = -I$(TOP) -I$(TOP_SRC) -I$(TOP_GUI) \
	$(GTK_CFLAGS) -DGUI_SOURCES -DCURDIR=$(CURRENT)
DPFLAGS = $(CFLAGS)

GLADEFILE = gtk-gnutella.glade

# We allow the target to fail since we're distribute the generated files
# with the sources, so even if they don't have glade, it will work.

# Unfortunately there are problems with generating the sources from
# the glade file. If the user does not have the right setup then the
# compilation will fail, and most users won't be able to correct this
# by using the distributed sources instead. Thus: commented out until
# better times.
#$(GLADE_GEN): $(GLADEFILE) $(REMOTE_GLADE)
#	-$(GLADE) --write-source $(GLADEFILE)
#	touch $(GLADE_GEN)

GTK_SHARED = ../gtk-shared

callbacks.c: $(GTK_SHARED)/callbacks.c
	$(RM) callbacks.c
	$(CP) $(GTK_SHARED)/callbacks.c .

callbacks.h: $(GTK_SHARED)/callbacks.h
	$(RM) callbacks.h
	$(CP) $(GTK_SHARED)/callbacks.h .


interface-glade.o: interface-glade.c
	$(CC) -c $(JCFLAGS) -O0 -w $<

depend:: $(REMOTE_GLADE)

local_realclean::
	$(RM) $(REMOTE_GLADE)

!NO!SUBS!
case "$d_usegtk1" in
define)
	$spitshell >>Makefile <<'!NO!SUBS!'

all:: libgtk1.a

local_realclean::
	$(RM) libgtk1.a

libgtk1.a:  $(OBJ)
	$(RM) $@
	$(AR) $@  $(OBJ)
	$(RANLIB) $@
!NO!SUBS!
	;;
esac
$spitshell >>Makefile <<'!NO!SUBS!'

local_depend:: ../../../../mkdep

../../../../mkdep:
	@echo "You have to run Configure in $(TOP) first."; exit 1

depend:: local_depend
local_depend::
	($(SED) '/^# DO NOT DELETE/q' Makefile && \
	$(MKDEP) $(SOURCES) | \
	$(SED) -e 's:/usr/lib[^ ]*::g; s:$(USRINC)[^ ]*::g; ' \
		-e '/: / b print' -e '$$ b print' -e 'H; d; n; : print' \
		-e 'x; s/\\$$//; s/\\\n//g; s/  */ /g; s/ :/:/;' -e '/: *$$/d' \
	) > Makefile.new
	cp Makefile Makefile.bak
	cp Makefile.new Makefile
	$(RM) Makefile.new

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

########################################################################
# Dependencies generated by make depend
# DO NOT DELETE THIS LINE -- make depend relies on it

# Put nothing here or make depend will gobble it up
.FORCE_DEPEND::
	@echo "You must run 'make depend' in $(TOP) first."; exit 1
!NO!SUBS!
chmod 644 Makefile
$eunicefix Makefile

