: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-180]
: $X-Id: Jmake.tmpl 156 2012-12-19 16:44:39Z rmanfredi $

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
CURRENT=src/ui/gtk
DIR=`echo $CURRENT/ | sed -e 's/\.\///g'`
echo "Extracting ${DIR}Makefile (with variable substitutions)"

DATE=`date`

$spitshell >Makefile <<!GROK!THIS!
########################################################################
# Makefile generated from Makefile.SH on $DATE

SHELL = /bin/sh
JMAKE = jmake
TOP = ../../..
CURRENT = $CURRENT
DIR = $DIR

########################################################################
# Parameters set by Configure -- edit config.sh if changes are needed

AR = ar rc
CC = $cc
CTAGS = ctags
JCFLAGS = \$(CFLAGS) $optimize $pthread $ccflags $large
JCPPFLAGS = $cppflags
LN = $ln
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RANLIB = $ranlib
RM = $rm -f
SED = $sed

########################################################################
# Automatically generated parameters -- do not edit

SUBDIRS = gtk1 gtk2
USRINC = $usrinc
GTK_LDFLAGS =  $gtkldflags
SOURCES =   \$(LSRC)
OBJECTS =   \$(LOBJ)
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
# $X-Id: Jmake.rules 174 2014-04-05 08:19:48Z rmanfredi $

########################################################################
# Force 'make depend' to be performed first -- do not edit

all:: .FORCE_DEPEND

.FORCE_DEPEND::

########################################################################
# Start of Jmakefile

# $X-Id$

LSRC = \
	clipboard.c \
	downloads_common.c \
	drag.c \
	drop.c \
	filter.c \
	filter_cb.c \
	filter_core.c \
	gnet_stats_common.c \
	gtk-missing.c \
	gtkcolumnchooser.c \
	hcache_common.c \
	html_view.c \
	icon.c \
	main.c \
	main_cb.c \
	misc.c \
	nodes_common.c \
	search_common.c \
	search_xml.c \
	settings.c \
	settings_cb.c \
	statusbar.c \
	upload_stats.c \
	upload_stats_cb.c \
	uploads_cb.c \
	uploads_common.c \
	visual_progress.c

LOBJ = \
	clipboard.o \
	downloads_common.o \
	drag.o \
	drop.o \
	filter.o \
	filter_cb.o \
	filter_core.o \
	gnet_stats_common.o \
	gtk-missing.o \
	gtkcolumnchooser.o \
	hcache_common.o \
	html_view.o \
	icon.o \
	main.o \
	main_cb.o \
	misc.o \
	nodes_common.o \
	search_common.o \
	search_xml.o \
	settings.o \
	settings_cb.o \
	statusbar.o \
	upload_stats.o \
	upload_stats_cb.o \
	uploads_cb.o \
	uploads_common.o \
	visual_progress.o 

TOP_SRC = ../..
TOP_GUI = ..

# Those extra flags are expected to be user-defined
CFLAGS = -I$(TOP) -I$(TOP_SRC) -I$(TOP_GUI) \
	$(GTK_CFLAGS) -DGUI_SOURCES -DCURDIR=$(CURRENT)
DPFLAGS = $(CFLAGS)

IF = ../../if
GNET_PROPS = gnet_property.h

.FORCE:

$(IF)/$(GNET_PROPS): .FORCE
	@echo "Checking "$(GNET_PROPS)" in "$(IF)"..."
	cd $(IF); $(MAKE) $(GNET_PROPS)
	@echo "Continuing in $(CURRENT)..."

libgtk-common.a:  $(IF)/$(GNET_PROPS)

depend:: sub_depend

sub_depend::
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "Depending" "in $(DIR)$$i..."; \
			$(MAKE) $(MFLAGS)  depend) || exit 1; \
	done

local_depend:: ../../../mkdep

../../../mkdep:
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

!NO!SUBS!
case "$d_headless" in
define) has_gui=false;;
*) has_gui=true;;
esac
$spitshell >>Makefile <<'!NO!SUBS!'

!NO!SUBS!
case "$d_usegtk1" in
define)
	$spitshell >>Makefile <<'!NO!SUBS!'
SDIR = gtk1
LIBRARY = libgtk1.a
!NO!SUBS!
	;;
esac
$spitshell >>Makefile <<'!NO!SUBS!'
!NO!SUBS!
case "$d_usegtk2" in
define)
	$spitshell >>Makefile <<'!NO!SUBS!'
SDIR = gtk2
LIBRARY = libgtk2.a
!NO!SUBS!
	;;
esac
$spitshell >>Makefile <<'!NO!SUBS!'

!NO!SUBS!
case "$has_gui" in
true)
	$spitshell >>Makefile <<'!NO!SUBS!'

all:: libgtk-common.a

local_realclean::
	$(RM) libgtk-common.a

libgtk-common.a:  $(LOBJ)
	$(RM) $@
	$(AR) $@  $(LOBJ)
	$(RANLIB) $@

$(SDIR)/support-glade.h: .FORCE
	@echo "Checking "support-glade.h" in "$(SDIR)"..."
	cd $(SDIR); $(MAKE) support-glade.h
	@echo "Continuing in $(CURRENT)..."

libgtk-common.a:  $(SDIR)/support-glade.h

all:: libgtkx.a

local_realclean::
	$(RM) libgtkx.a

$(SDIR)/$(LIBRARY): .FORCE
	@echo "Checking "$(LIBRARY)" in "$(SDIR)"..."
	cd $(SDIR); $(MAKE) $(LIBRARY)
	@echo "Continuing in $(CURRENT)..."

libgtkx.a:  $(SDIR)/$(LIBRARY)

libgtkx.a: $(SDIR)/$(LIBRARY)
	$(RM) $@
	$(LN) $(SDIR)/$(LIBRARY) $@
	$(RANLIB) $@
!NO!SUBS!
	;;
esac
$spitshell >>Makefile <<'!NO!SUBS!'

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

