: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-25]
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
CURRENT=src/lib
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
JCFLAGS = \$(CFLAGS) $optimize $ccflags $large
JCPPFLAGS = $cppflags
JYFLAGS = \$(YFLAGS) $yaccflags
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RANLIB = $ranlib
RM = $rm -f
SED = $sed
YACC = $yacc

########################################################################
# Automatically generated parameters -- do not edit

USRINC = $usrinc
SOURCES =  \$(LSRC)
OBJECTS =  \$(LOBJ)
GLIB_CFLAGS =  $glibcflags
DBUS_CFLAGS =  $dbuscflags

########################################################################
# New suffixes and associated building rules -- edit with care

.c.o:
	\$(RM) \$@
	\$(CC) -c \$(JCFLAGS) \$<

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules 18 2006-12-27 10:35:09Z rmanfredi $

########################################################################
# Force 'make depend' to be performed first -- do not edit

.FORCE_DEPEND::

all:: .FORCE_DEPEND

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile 16436 2009-04-07 19:13:35Z rmanfredi $

LSRC = \
	adns.c \
	aging.c \
	ascii.c \
	atoms.c \
	base16.c \
	base32.c \
	base64.c \
	bg.c \
	bstr.c \
	cobs.c \
	compat_pio.c \
	compat_sleep_ms.c \
	cq.c \
	crash.c \
	crc.c \
	dbmap.c \
	dbmw.c \
	dbus_util.c \
	debug.c \
	entropy.c \
	eval.c \
	event.c \
	fast_assert.c \
	fifo.c \
	file.c \
	fragcheck.c \
	fs_free_space.c \
	getdate.c \
	getline.c \
	getphysmemsize.c \
	glib-missing.c \
	gnet_host.c \
	halloc.c \
	hashlist.c \
	hashtable.c \
	header.c \
	host_addr.c \
	html.c \
	idtable.c \
	inputevt.c \
	iprange.c \
	iso3166.c \
	list.c \
	magnet.c \
	malloc.c \
	map.c \
	mime_type.c \
	misc.c \
	options.c \
	pagetable.c \
	palloc.c \
	patricia.c \
	pattern.c \
	pmsg.c \
	prop.c \
	sequence.c \
	sha1.c \
	slist.c \
	socket.c \
	sorted_array.c \
	stats.c \
	strtok.c \
	tea.c \
	tiger.c \
	tigertree.c \
	tm.c \
	url.c \
	url_factory.c \
	urn.c \
	utf8.c \
	vendors.c \
	vmm.c \
	walloc.c \
	watcher.c \
	wd.c \
	wordvec.c \
	zalloc.c \
	zlib_util.c

LOBJ = \
	adns.o \
	aging.o \
	ascii.o \
	atoms.o \
	base16.o \
	base32.o \
	base64.o \
	bg.o \
	bstr.o \
	cobs.o \
	compat_pio.o \
	compat_sleep_ms.o \
	cq.o \
	crash.o \
	crc.o \
	dbmap.o \
	dbmw.o \
	dbus_util.o \
	debug.o \
	entropy.o \
	eval.o \
	event.o \
	fast_assert.o \
	fifo.o \
	file.o \
	fragcheck.o \
	fs_free_space.o \
	getdate.o \
	getline.o \
	getphysmemsize.o \
	glib-missing.o \
	gnet_host.o \
	halloc.o \
	hashlist.o \
	hashtable.o \
	header.o \
	host_addr.o \
	html.o \
	idtable.o \
	inputevt.o \
	iprange.o \
	iso3166.o \
	list.o \
	magnet.o \
	malloc.o \
	map.o \
	mime_type.o \
	misc.o \
	options.o \
	pagetable.o \
	palloc.o \
	patricia.o \
	pattern.o \
	pmsg.o \
	prop.o \
	sequence.o \
	sha1.o \
	slist.o \
	socket.o \
	sorted_array.o \
	stats.o \
	strtok.o \
	tea.o \
	tiger.o \
	tigertree.o \
	tm.o \
	url.o \
	url_factory.o \
	urn.o \
	utf8.o \
	vendors.o \
	vmm.o \
	walloc.o \
	watcher.o \
	wd.o \
	wordvec.o \
	zalloc.o \
	zlib_util.o 

# Those extra flags are expected to be user-defined
CFLAGS = -I$(TOP) -I.. $(GLIB_CFLAGS) $(DBUS_CFLAGS) -DCURDIR=$(CURRENT)
DPFLAGS = $(CFLAGS)

all:: libshared.a

local_realclean::
	$(RM) libshared.a

libshared.a: $(LOBJ)
	$(RM) $@
	$(AR) $@ $(LOBJ)
	$(RANLIB) $@

depend:: ../../mkdep

../../mkdep:
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

getdate.c: getdate.y
	-@if test -f $(TOP)/.package; then \
		echo "	$(YACC) $(JYFLAGS) $<"; \
		$(YACC) $(JYFLAGS) $<; \
		echo "	$(MV) y.tab.c $@"; \
		$(MV) y.tab.c $@; else touch $@; fi

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

