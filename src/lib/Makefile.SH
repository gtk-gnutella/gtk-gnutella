: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-255]
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
_EXE = $_exe
JCFLAGS = \$(CFLAGS) $optimize $pthread $ccflags $large
JCPPFLAGS = $cppflags
JLDFLAGS = \$(LDFLAGS) $optimize $pthread $ldflags
JYFLAGS = \$(YFLAGS) $yaccflags
LIBS = $libs
LN = $ln
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RANLIB = $ranlib
RM = $rm -f
SED = $sed
YACC = $yacc

########################################################################
# Automatically generated parameters -- do not edit

USRINC = $usrinc
COMMON_LIBS =  $libs
GLIB_CFLAGS =  $glibcflags
GLIB_LDFLAGS =  $glibldflags
SOURCES =  \$(LSRC)  filelock-test.c  float-test.c  ftw-test.c  launch-test.c  pattern-test.c  random-test.c  sort-test.c  spopen-test.c  stat-test.c  thread-test.c
OBJECTS =  \$(LOBJ)  filelock-test.o  float-test.o  ftw-test.o  launch-test.o  pattern-test.o  random-test.o  sort-test.o  spopen-test.o  stat-test.o  thread-test.o
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
# $X-Id$

########################################################################
# Force 'make depend' to be performed first -- do not edit

all:: .FORCE_DEPEND

.FORCE_DEPEND::

########################################################################
# Start of Jmakefile

# $X-Id$

bit_array.h: bit_array.ht bit_generic.ht
	$(TOP)/scripts/generic-cat bit_array.ht bit_generic.ht array >$@

bit_array.c: bit_generic.ct
	$(TOP)/scripts/generic-cat /dev/null bit_generic.ct array >$@

all:: bit_array.h bit_array.c
depend:: bit_array.h bit_array.c
local_realclean::
	$(RM) bit_array.h bit_array.c

bit_field.h: bit_field.ht bit_generic.ht
	$(TOP)/scripts/generic-cat bit_field.ht bit_generic.ht field >$@

bit_field.c: bit_generic.ct
	$(TOP)/scripts/generic-cat /dev/null bit_generic.ct field >$@

all:: bit_field.h bit_field.c
depend:: bit_field.h bit_field.c
local_realclean::
	$(RM) bit_field.h bit_field.c

htable.h: hgeneric.ht
	$(TOP)/scripts/generic-pp /dev/null hgeneric.ht table ckeyval TABLE >$@

htable.c: hgeneric.ct
	$(TOP)/scripts/generic-pp /dev/null hgeneric.ct table ckeyval TABLE >$@

all:: htable.h htable.c
depend:: htable.h htable.c
local_realclean::
	$(RM) htable.h htable.c

hset.h: hgeneric.ht
	$(TOP)/scripts/generic-pp /dev/null hgeneric.ht set cdata SET >$@

hset.c: hgeneric.ct
	$(TOP)/scripts/generic-pp /dev/null hgeneric.ct set cdata SET >$@

all:: hset.h hset.c
depend:: hset.h hset.c
local_realclean::
	$(RM) hset.h hset.c

LSRC = \
	adns.c \
	aging.c \
	aje.c \
	alloca.c \
	aq.c \
	arc4random.c \
	argv.c \
	ascii.c \
	atio.c \
	atoms.c \
	balloc.c \
	barrier.c \
	base16.c \
	base32.c \
	base64.c \
	bfd_util.c \
	bg.c \
	bigint.c \
	bit_array.c \
	bit_field.c \
	bsearch.c \
	bstr.c \
	buf.c \
	chi2.c \
	ckalloc.c \
	cmwc.c \
	cobs.c \
	compat_gettid.c \
	compat_misc.c \
	compat_pause.c \
	compat_pio.c \
	compat_poll.c \
	compat_sendfile.c \
	compat_setjmp.c \
	compat_sleep_ms.c \
	compat_statvfs.c \
	compat_un.c \
	compat_usleep.c \
	concat.c \
	cond.c \
	constants.c \
	cpufreq.c \
	cq.c \
	crash.c \
	crc.c \
	cstr.c \
	dam.c \
	dbmap.c \
	dbmw.c \
	dbstore.c \
	dbus_util.c \
	debug.c \
	dl_util.c \
	dualhash.c \
	elist.c \
	entropy.c \
	erbtree.c \
	eslist.c \
	etree.c \
	eval.c \
	event.c \
	evq.c \
	exit.c \
	exit2str.c \
	fast_assert.c \
	fd.c \
	file.c \
	file_object.c \
	filehead.c \
	filelock.c \
	filename.c \
	float.c \
	fragcheck.c \
	frand.c \
	fs_free_space.c \
	ftw.c \
	gen-iprange.c \
	gentime.c \
	getcpucount.c \
	getdate.c \
	getgateway.c \
	gethomedir.c \
	getline.c \
	getphysmemsize.c \
	glib-missing.c \
	glog.c \
	gnet_host.c \
	halloc.c \
	hash.c \
	hashing.c \
	hashlist.c \
	hashtable.c \
	header.c \
	hevset.c \
	hikset.c \
	host_addr.c \
	hset.c \
	hstrfn.c \
	htable.c \
	html.c \
	http_range.c \
	idtable.c \
	inputevt.c \
	iprange.c \
	ipset.c \
	iso3166.c \
	launch.c \
	leak.c \
	list.c \
	listener.c \
	log.c \
	magnet.c \
	malloc.c \
	map.c \
	mem.c \
	mempcpy.c \
	memusage.c \
	mime_type.c \
	mingw32.c \
	misc.c \
	mtwist.c \
	mutex.c \
	nid.c \
	nv.c \
	offtime.c \
	ohash_table.c \
	omalloc.c \
	once.c \
	options.c \
	ostream.c \
	pagetable.c \
	palloc.c \
	parse.c \
	path.c \
	patricia.c \
	pattern.c \
	plist.c \
	pmsg.c \
	pow2.c \
	product.c \
	progname.c \
	prop.c \
	pslist.c \
	qlock.c \
	rand31.c \
	random.c \
	rbtree.c \
	regex.c \
	ripening.c \
	rwlock.c \
	sectoken.c \
	semaphore.c \
	sequence.c \
	setproctitle.c \
	sha1.c \
	shuffle.c \
	signal.c \
	slist.c \
	smsort.c \
	sorted_array.c \
	spinlock.c \
	spopen.c \
	stacktrace.c \
	stats.c \
	str.c \
	stringify.c \
	strpcpy.c \
	strtok.c \
	strvec.c \
	symbols.c \
	symtab.c \
	tea.c \
	teq.c \
	thread.c \
	tiger.c \
	tigertree.c \
	timestamp.c \
	tm.c \
	tmalloc.c \
	tokenizer.c \
	tqsort.c \
	tsig.c \
	url.c \
	urn.c \
	utf8.c \
	vector.c \
	vendors.c \
	vmea.c \
	vmm.c \
	vsort.c \
	waiter.c \
	walloc.c \
	watcher.c \
	wd.c \
	well.c \
	win32dlp.c \
	wordvec.c \
	wq.c \
	xmalloc.c \
	xslist.c \
	xsort.c \
	xsort_data.c \
	xxtea.c \
	zalloc.c \
	zlib_util.c

LOBJ = \
	adns.o \
	aging.o \
	aje.o \
	alloca.o \
	aq.o \
	arc4random.o \
	argv.o \
	ascii.o \
	atio.o \
	atoms.o \
	balloc.o \
	barrier.o \
	base16.o \
	base32.o \
	base64.o \
	bfd_util.o \
	bg.o \
	bigint.o \
	bit_array.o \
	bit_field.o \
	bsearch.o \
	bstr.o \
	buf.o \
	chi2.o \
	ckalloc.o \
	cmwc.o \
	cobs.o \
	compat_gettid.o \
	compat_misc.o \
	compat_pause.o \
	compat_pio.o \
	compat_poll.o \
	compat_sendfile.o \
	compat_setjmp.o \
	compat_sleep_ms.o \
	compat_statvfs.o \
	compat_un.o \
	compat_usleep.o \
	concat.o \
	cond.o \
	constants.o \
	cpufreq.o \
	cq.o \
	crash.o \
	crc.o \
	cstr.o \
	dam.o \
	dbmap.o \
	dbmw.o \
	dbstore.o \
	dbus_util.o \
	debug.o \
	dl_util.o \
	dualhash.o \
	elist.o \
	entropy.o \
	erbtree.o \
	eslist.o \
	etree.o \
	eval.o \
	event.o \
	evq.o \
	exit.o \
	exit2str.o \
	fast_assert.o \
	fd.o \
	file.o \
	file_object.o \
	filehead.o \
	filelock.o \
	filename.o \
	float.o \
	fragcheck.o \
	frand.o \
	fs_free_space.o \
	ftw.o \
	gen-iprange.o \
	gentime.o \
	getcpucount.o \
	getdate.o \
	getgateway.o \
	gethomedir.o \
	getline.o \
	getphysmemsize.o \
	glib-missing.o \
	glog.o \
	gnet_host.o \
	halloc.o \
	hash.o \
	hashing.o \
	hashlist.o \
	hashtable.o \
	header.o \
	hevset.o \
	hikset.o \
	host_addr.o \
	hset.o \
	hstrfn.o \
	htable.o \
	html.o \
	http_range.o \
	idtable.o \
	inputevt.o \
	iprange.o \
	ipset.o \
	iso3166.o \
	launch.o \
	leak.o \
	list.o \
	listener.o \
	log.o \
	magnet.o \
	malloc.o \
	map.o \
	mem.o \
	mempcpy.o \
	memusage.o \
	mime_type.o \
	mingw32.o \
	misc.o \
	mtwist.o \
	mutex.o \
	nid.o \
	nv.o \
	offtime.o \
	ohash_table.o \
	omalloc.o \
	once.o \
	options.o \
	ostream.o \
	pagetable.o \
	palloc.o \
	parse.o \
	path.o \
	patricia.o \
	pattern.o \
	plist.o \
	pmsg.o \
	pow2.o \
	product.o \
	progname.o \
	prop.o \
	pslist.o \
	qlock.o \
	rand31.o \
	random.o \
	rbtree.o \
	regex.o \
	ripening.o \
	rwlock.o \
	sectoken.o \
	semaphore.o \
	sequence.o \
	setproctitle.o \
	sha1.o \
	shuffle.o \
	signal.o \
	slist.o \
	smsort.o \
	sorted_array.o \
	spinlock.o \
	spopen.o \
	stacktrace.o \
	stats.o \
	str.o \
	stringify.o \
	strpcpy.o \
	strtok.o \
	strvec.o \
	symbols.o \
	symtab.o \
	tea.o \
	teq.o \
	thread.o \
	tiger.o \
	tigertree.o \
	timestamp.o \
	tm.o \
	tmalloc.o \
	tokenizer.o \
	tqsort.o \
	tsig.o \
	url.o \
	urn.o \
	utf8.o \
	vector.o \
	vendors.o \
	vmea.o \
	vmm.o \
	vsort.o \
	waiter.o \
	walloc.o \
	watcher.o \
	wd.o \
	well.o \
	win32dlp.o \
	wordvec.o \
	wq.o \
	xmalloc.o \
	xslist.o \
	xsort.o \
	xsort_data.o \
	xxtea.o \
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

getdate.c: getdate.y
	-@if test -f $(TOP)/.package; then \
		echo "	$(YACC) $(JYFLAGS) $<"; \
		$(YACC) $(JYFLAGS) $<; \
		echo "	$(MV) y.tab.c $@"; \
		$(MV) y.tab.c $@; else touch $@; fi

getdate: getdate.c
	$(CC) -o $@ $(JCFLAGS) -DTEST $< libshared.a $(LIBS)

#
# Floating point formatting tests
#
# The "bad-fixed" target show formatting errors: the output file MUST be empty
# or there are bugs in the floating point formatting routine.
#

LDFLAGS =
LIBS = $(GLIB_LDFLAGS) $(COMMON_LIBS)
IF = ../if

floats: floats.bz2
	bzip2 -c -d floats.bz2 >$@

float-dragon.out: float-dragon_out.bz2
	bzip2 -c -d float-dragon_out.bz2 >$@

bad-fixed: float-test floats
	./float-test floats compare >$@

bad-free: float-test floats float-dragon.out
	./float-test floats dragon | diff -u - float-dragon.out >$@

float-times: float-test floats
	uname -a >$@
	echo -n "base:    " >>$@
	sh -c "time ./float-test floats base" >>$@ 2>&1
	echo -n "sprintf: " >>$@
	sh -c "time ./float-test floats sprintf" >>$@ 2>&1
	echo -n "printf:  " >>$@
	sh -c "time ./float-test floats printf > /dev/null" >>$@ 2>&1
	echo -n "fixed:   " >>$@
	sh -c "time ./float-test floats fixed > /dev/null" >>$@ 2>&1
	echo -n "free:    " >>$@
	sh -c "time ./float-test floats dragon > /dev/null" >>$@ 2>&1

ftw-check: ftw-test
	./ftw-mktree
	./ftw-test -s ftw-root | diff -u - ftw-root.out >$@

local_clean::
	$(RM) floats float-dragon.out bad-fixed float-times ftw-check
	./ftw-mktree -r

all:: filelock-test

local_realclean::
	$(RM) filelock-test$(_EXE)

filelock-test:  filelock-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  filelock-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: float-test

local_realclean::
	$(RM) float-test$(_EXE)

float-test:  float-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  float-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: ftw-test

local_realclean::
	$(RM) ftw-test$(_EXE)

ftw-test:  ftw-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  ftw-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: launch-test

local_realclean::
	$(RM) launch-test$(_EXE)

launch-test:  launch-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  launch-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: pattern-test

local_realclean::
	$(RM) pattern-test$(_EXE)

pattern-test:  pattern-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  pattern-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: random-test

local_realclean::
	$(RM) random-test$(_EXE)

random-test:  random-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  random-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: sort-test

local_realclean::
	$(RM) sort-test$(_EXE)

sort-test:  sort-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  sort-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: spopen-test

local_realclean::
	$(RM) spopen-test$(_EXE)

spopen-test:  spopen-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  spopen-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: stat-test

local_realclean::
	$(RM) stat-test$(_EXE)

stat-test:  stat-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  stat-test.o $(JLDFLAGS)  libshared.a $(LIBS)

all:: thread-test

local_realclean::
	$(RM) thread-test$(_EXE)

thread-test:  thread-test.o  libshared.a
	-$(RM) $@$(_EXE)
	if test -f $@$(_EXE); then \
		$(MV) $@$(_EXE) $@~$(_EXE); fi
	$(CC) -o $@$(_EXE)  thread-test.o $(JLDFLAGS)  libshared.a $(LIBS)

gen-iprange.c:   $(IF)/gen/iprange.c
	$(RM) -f $@
	$(LN) $? $@

local_depend::  gen-iprange.c

local_realclean::
	$(RM) -f  gen-iprange.c

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

