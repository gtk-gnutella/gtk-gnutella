: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-171]
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
CURRENT=src/sdbm
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

AR = ar rc
CC = $cc
CTAGS = ctags
_EXE = $_exe
JCFLAGS = \$(CFLAGS) $optimize $pthread $ccflags $large
JCPPFLAGS = $cppflags
JLDFLAGS = \$(LDFLAGS) $optimize $pthread $ldflags
LIBS = $libs
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RANLIB = $ranlib
RM = $rm -f
SED = $sed

########################################################################
# Automatically generated parameters -- do not edit

USRINC = $usrinc
GLIB_LDFLAGS =  $glibldflags
SOURCES =   \$(SRC)  \$(DBA_SRC)  \$(DBU_SRC)  \$(DBE_SRC)  \$(DBT_SRC)
OBJECTS =   \$(OBJ)  \$(DBA_OBJ)  \$(DBU_OBJ)  \$(DBE_OBJ)  \$(DBT_OBJ)
GLIB_CFLAGS =  $glibcflags
COMMON_LIBS =  $libs

########################################################################
# New suffixes and associated building rules -- edit with care

.c.o:
	\$(RM) \$@
	\$(CC) -c \$(JCFLAGS) \$<

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules 106 2011-11-25 20:36:12Z rmanfredi $

########################################################################
# Force 'make depend' to be performed first -- do not edit

all:: .FORCE_DEPEND

.FORCE_DEPEND::

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile 11185 2006-06-25 22:00:15Z cbiere $

SRC = \
	big.c \
	hash.c \
	lru.c \
	pair.c \
	sdbm.c

OBJ = \
	big.o \
	hash.o \
	lru.o \
	pair.o \
	sdbm.o 

SDBM_FLAGS = -DSDBM -DDUFF

# Those extra flags are expected to be user-defined
CFLAGS = -I$(TOP) -I.. $(GLIB_CFLAGS) $(SDBM_FLAGS) -DCURDIR=$(CURRENT)
DPFLAGS = $(CFLAGS)

all:: libsdbm.a

local_realclean::
	$(RM) libsdbm.a

libsdbm.a:  $(OBJ)
	$(RM) $@
	$(AR) $@  $(OBJ)
	$(RANLIB) $@

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

DBA_SRC = \
	dba.c \
	util.c

DBU_SRC = \
	dbu.c \
	util.c

DBE_SRC = \
	dbe.c \
	util.c

DBT_SRC = \
	dbt.c \
	util.c

DBA_OBJ = \
	dba.o \
	util.o 

DBU_OBJ = \
	dbu.o \
	util.o 

DBE_OBJ = \
	dbe.o \
	util.o 

DBT_OBJ = \
	dbt.o \
	util.o 

LDFLAGS =
LIBS = -L. -lsdbm -L../lib -lshared $(GLIB_LDFLAGS) $(COMMON_LIBS)

dbu dbe dbt: libsdbm.a

.FORCE:

../lib/libshared.a: .FORCE
	@echo "Checking "libshared.a" in "../lib"..."
	cd ../lib; $(MAKE) libshared.a
	@echo "Continuing in $(CURRENT)..."

dbu:  ../lib/libshared.a

dbe:  ../lib/libshared.a

dbt:  ../lib/libshared.a

all:: dba

local_realclean::
	$(RM) dba$(_EXE)

dba:  $(DBA_OBJ)
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  $(DBA_OBJ) $(JLDFLAGS) $(LIBS)

all:: dbu

local_realclean::
	$(RM) dbu$(_EXE)

dbu:  $(DBU_OBJ)
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  $(DBU_OBJ) $(JLDFLAGS) $(LIBS)

all:: dbe

local_realclean::
	$(RM) dbe$(_EXE)

dbe:  $(DBE_OBJ)
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  $(DBE_OBJ) $(JLDFLAGS) $(LIBS)

all:: dbt

local_realclean::
	$(RM) dbt$(_EXE)

dbt:  $(DBT_OBJ)
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  $(DBT_OBJ) $(JLDFLAGS) $(LIBS)

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

