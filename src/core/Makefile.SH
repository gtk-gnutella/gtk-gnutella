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
XML2_CFLAGS =  $xmlcflags
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
# $X-Id: Jmake.rules 18 2006-12-27 10:35:09Z rmanfredi $

########################################################################
# Force 'make depend' to be performed first -- do not edit

.FORCE_DEPEND::

all:: .FORCE_DEPEND

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile 16157 2009-03-15 11:28:30Z rmanfredi $

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
	gmsg.c \
	gnet_stats.c \
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
	pproxy.c \
	qhit.c \
	qrp.c \
	routing.c \
	rx.c \
	rx_chunk.c \
	rx_inflate.c \
	rx_link.c \
	rxbuf.c \
	search.c \
	settings.c \
	share.c \
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
	udp.c \
	uhc.c \
	upload_stats.c \
	uploads.c \
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
	gmsg.o \
	gnet_stats.o \
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
	pproxy.o \
	qhit.o \
	qrp.o \
	routing.o \
	rx.o \
	rx_chunk.o \
	rx_inflate.o \
	rx_link.o \
	rxbuf.o \
	search.o \
	settings.o \
	share.o \
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
	udp.o \
	uhc.o \
	upload_stats.o \
	uploads.o \
	verify.o \
	verify_sha1.o \
	verify_tth.o \
	version.o \
	vmsg.o \
	whitelist.o 

# Those extra flags are expected to be user-defined
CFLAGS = -I$(TOP) -I.. $(GLIB_CFLAGS) $(XML2_CFLAGS) $(GNUTLS_CFLAGS) \
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

