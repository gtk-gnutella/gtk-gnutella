: Makefile.SH generated from Jmake.tmpl and Jmakefile [jmake 3.5-147]
: $X-Id: Jmake.tmpl 69 2011-01-09 13:57:07Z rmanfredi $

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
CURRENT=src/core
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
MKDEP = $mkdep \$(DPFLAGS) \$(JCPPFLAGS) --
MV = $mv
RANLIB = $ranlib
RM = $rm -f
SED = $sed

########################################################################
# Automatically generated parameters -- do not edit

USRINC = $usrinc
SOURCES =   \$(SRC)
OBJECTS =   \$(OBJ)
SOCKER_CFLAGS =  $sockercflags
GLIB_CFLAGS =  $glibcflags
GNUTLS_CFLAGS =  $gnutlscflags

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

SRC = \
	alive.c \
	ban.c \
	bh_download.c \
	bh_upload.c \
	bitzi.c \
	bogons.c \
	bsched.c \
	clock.c \
	ctl.c \
	dh.c \
	dime.c \
	dmesh.c \
	downloads.c \
	dq.c \
	dump.c \
	extensions.c \
	features.c \
	file_object.c \
	fileinfo.c \
	gdht.c \
	geo_ip.c \
	ggep.c \
	ggep_type.c \
	ghc.c \
	gmsg.c \
	gnet_stats.c \
	guess.c \
	guid.c \
	hcache.c \
	hostiles.c \
	hosts.c \
	hsep.c \
	http.c \
	huge.c \
	ignore.c \
	inet.c \
	ioheader.c \
	ipp_cache.c \
	ipv6-ready.c \
	local_shell.c \
	matching.c \
	move.c \
	mq.c \
	mq_tcp.c \
	mq_udp.c \
	namesize.c \
	nodes.c \
	ntp.c \
	oob.c \
	oob_proxy.c \
	parq.c \
	pcache.c \
	pdht.c \
	pproxy.c \
	publisher.c \
	qhit.c \
	qrp.c \
	routing.c \
	rx.c \
	rx_chunk.c \
	rx_inflate.c \
	rx_link.c \
	rx_ut.c \
	rxbuf.c \
	search.c \
	settings.c \
	share.c \
	soap.c \
	sockets.c \
	spam.c \
	spam_sha1.c \
	sq.c \
	thex_download.c \
	thex_upload.c \
	tls_common.c \
	token.c \
	topless.c \
	tsync.c \
	tth_cache.c \
	tx.c \
	tx_chunk.c \
	tx_deflate.c \
	tx_dgram.c \
	tx_link.c \
	tx_ut.c \
	udp.c \
	udp_sched.c \
	uhc.c \
	upload_stats.c \
	uploads.c \
	urpc.c \
	verify.c \
	verify_sha1.c \
	verify_tth.c \
	version.c \
	vmsg.c \
	whitelist.c

OBJ = \
	alive.o \
	ban.o \
	bh_download.o \
	bh_upload.o \
	bitzi.o \
	bogons.o \
	bsched.o \
	clock.o \
	ctl.o \
	dh.o \
	dime.o \
	dmesh.o \
	downloads.o \
	dq.o \
	dump.o \
	extensions.o \
	features.o \
	file_object.o \
	fileinfo.o \
	gdht.o \
	geo_ip.o \
	ggep.o \
	ggep_type.o \
	ghc.o \
	gmsg.o \
	gnet_stats.o \
	guess.o \
	guid.o \
	hcache.o \
	hostiles.o \
	hosts.o \
	hsep.o \
	http.o \
	huge.o \
	ignore.o \
	inet.o \
	ioheader.o \
	ipp_cache.o \
	ipv6-ready.o \
	local_shell.o \
	matching.o \
	move.o \
	mq.o \
	mq_tcp.o \
	mq_udp.o \
	namesize.o \
	nodes.o \
	ntp.o \
	oob.o \
	oob_proxy.o \
	parq.o \
	pcache.o \
	pdht.o \
	pproxy.o \
	publisher.o \
	qhit.o \
	qrp.o \
	routing.o \
	rx.o \
	rx_chunk.o \
	rx_inflate.o \
	rx_link.o \
	rx_ut.o \
	rxbuf.o \
	search.o \
	settings.o \
	share.o \
	soap.o \
	sockets.o \
	spam.o \
	spam_sha1.o \
	sq.o \
	thex_download.o \
	thex_upload.o \
	tls_common.o \
	token.o \
	topless.o \
	tsync.o \
	tth_cache.o \
	tx.o \
	tx_chunk.o \
	tx_deflate.o \
	tx_dgram.o \
	tx_link.o \
	tx_ut.o \
	udp.o \
	udp_sched.o \
	uhc.o \
	upload_stats.o \
	uploads.o \
	urpc.o \
	verify.o \
	verify_sha1.o \
	verify_tth.o \
	version.o \
	vmsg.o \
	whitelist.o 

# Those extra flags are expected to be user-defined
CFLAGS = -I$(TOP) -I.. $(GLIB_CFLAGS) $(GNUTLS_CFLAGS) \
	$(SOCKER_CFLAGS) -DCORE_SOURCES -DCURDIR=$(CURRENT)
DPFLAGS = $(CFLAGS)

IF = ../if
GNET_PROPS = gnet_property.h

.FORCE:

$(IF)/$(GNET_PROPS): .FORCE
	@echo "Checking "$(GNET_PROPS)" in "$(IF)"..."
	cd $(IF); $(MAKE) $(GNET_PROPS)
	@echo "Continuing in $(CURRENT)..."

libcore.a:  $(IF)/$(GNET_PROPS)

all:: libcore.a

local_realclean::
	$(RM) libcore.a

libcore.a:  $(OBJ)
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

