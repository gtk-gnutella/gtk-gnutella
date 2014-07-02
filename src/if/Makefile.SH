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
CURRENT=src/if
DIR=`echo $CURRENT/ | sed -e 's/\.\///g'`
echo "Extracting ${DIR}Makefile (with variable substitutions)"

DATE=`date`

$spitshell >Makefile <<!GROK!THIS!
########################################################################
# Makefile generated from Makefile.SH on $DATE

SHELL = /bin/sh
JMAKE = jmake
TOP = ../..
CURRENT = $CURRENT
DIR = $DIR

########################################################################
# Parameters set by Configure -- edit config.sh if changes are needed

CC = $cc
CTAGS = ctags
JCFLAGS = \$(CFLAGS) $optimize $pthread $ccflags $large
JCPPFLAGS = $cppflags
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RM = $rm -f
SED = $sed

########################################################################
# Automatically generated parameters -- do not edit

SUBDIRS = bridge gen
USRINC = $usrinc
SOURCES =  gnet_property.c gui_property.c
GLIB_CFLAGS =  $glibcflags

########################################################################
# New suffixes and associated building rules -- edit with care

.c.o:
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

depend:: sub_depend

sub_depend::
	@case '${MFLAGS}' in *[ik]*) set +e;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "Depending" "in $(DIR)$$i..."; \
			$(MAKE) $(MFLAGS)  depend) || exit 1; \
	done

SOURCES = gnet_property.c gui_property.c

CFLAGS = -I$(TOP) -I.. $(GLIB_CFLAGS) -DCURDIR=$(CURRENT)
DPFLAGS = $(CFLAGS)

all:: properties

properties: gnet_property.c gui_property.c

gnet_property_priv.h  gnet_property.h  gnet_property.c: gnet_props.ag props.tpl
	-@if test -f $(TOP)/.package; then \
		echo "  autogen gnet_props.ag"; \
		autogen gnet_props.ag; \
	else touch $@; fi

gui_property_priv.h  gui_property.h  gui_property.c: gui_props.ag props.tpl
	-@if test -f $(TOP)/.package; then \
		echo "  autogen gui_props.ag"; \
		autogen gui_props.ag; \
	else touch $@; fi

all:: gnet_property.o

local_realclean::
	$(RM) gnet_property.o

all:: gui_property.o

local_realclean::
	$(RM) gui_property.o

local_depend:: ../../mkdep

../../mkdep:
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

