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
JCFLAGS = \$(CFLAGS) $optimize $ccflags $large
JLDFLAGS = \$(LDFLAGS) $optimize $ldflags
JYFLAGS = \$(YFLAGS) $yaccflags
L = $manext
LIBS = $libs
MANSRC = $installmansrc
$make_set_make
MKDEP = $mkdep \$(DPFLAGS) --
MV = $mv
PRIVLIB = $installprivlib
RM = $rm -f
SED = $sed
YACC = $yacc

########################################################################
# Automatically generated parameters -- do not edit

USRINC = $usrinc
GUI_GLADE_SRC =  $gladesrc
GTK_CFLAGS =  $gtkcflags
SOURCES =   getdate.y  \$(SRC)
GTK_LDFLAGS =  $gtkldflags
GLADEFILE =  ../$gladefile
XML2_LDFLAGS =  $xmlldflags
GUI_GLADE_OBJ =  $gladeobj
XML2_CFLAGS =  $xmlcflags
GLADE =  $glade
OBJECTS =   getdate.o  \$(OBJ) getdate.o

########################################################################
# New suffixes and associated building rules -- edit with care

.SUFFIXES: .y

.y.c:
	\$(YACC) \$(JYFLAGS) \$<
	\$(MV) y.tab.c \$@

.c.o:
	\$(CC) -c \$(JCFLAGS) \$<

!GROK!THIS!
$spitshell >>Makefile <<'!NO!SUBS!'
########################################################################
# Jmake rules for building libraries, programs, scripts, and data files
# $X-Id: Jmake.rules,v 3.0.1.6 1997/02/28 14:56:01 ram Exp ram $

########################################################################
# Force 'make depend' to be performed first -- do not edit

.FORCE_DEPEND::

all:: .FORCE_DEPEND

########################################################################
# Start of Jmakefile

# $X-Id: Jmakefile,v 1.5 2003/08/15 22:56:24 rmanfredi Exp $

GUI_GTK2 = \
	fileinfo_gui2.c \
	gnet_stats_gui2.c \
	monitor_cb2.c\
	monitor_gui2.c \
	nodes_cb2.c \
	nodes_gui2.c \
	search_cb2.c \
	search_gui2.c \
	search_stats_gui2.c \
	uploads_gui2.c \
	upload_stats_gui2.c

GUI_GTK1 = \
	fileinfo_gui.c \
	gnet_stats_gui.c \
	monitor_cb.c \
	monitor_gui.c \
	nodes_cb.c \
	nodes_gui.c \
	search_cb.c \
	search_gui.c \
	search_stats_gui.c \
	uploads_gui.c \
	upload_stats_gui.c 

GUI_COMMON = \
	callbacks.c \
	downloads_cb.c \
	downloads_gui.c \
	filter.c \
	filter_cb.c \
	filter_gui.c \
	gnet_stats_gui_common.c \
	gtkcolumnchooser.c \
	gtk-missing.c \
	gui.c \
	gui_property.c \
	main_cb.c \
	main_gui.c \
	nodes_gui_common.c \
	search_gui_common.c \
	settings_cb.c \
	settings_gui.c \
	statusbar_gui.c \
	uploads_cb.c \
	uploads_gui_common.c \
	upload_stats_cb.c

CORE = \
	adns.c \
	alive.c \
	atoms.c \
	ban.c \
	base32.c \
	base64.c \
	bg.c \
	bsched.c \
	clock.c \
	cobs.c \
	common.c \
	cq.c \
	crc.c \
	dmesh.c \
	downloads.c \
	eval.c \
	event.c \
	extensions.c \
	file.c \
	fileinfo.c \
	fuzzy.c \
	getline.c \
	ggep.c \
	ggep_type.c \
	glib-missing.c \
	gmsg.c \
	gnet_property.c \
	gnet_stats.c \
	guid.c \
	gwcache.c \
	hcache.c \
	header.c \
	hostiles.c \
	hosts.c \
	http.c \
	huge.c \
	icon.c \
	idtable.c \
	ignore.c \
	inet.c \
	inputevt.c \
	ioheader.c \
	main.c \
	matching.c \
	misc.c \
	move.c \
	mq.c \
	namesize.c \
	nodes.c \
	parq.c \
	pcache.c \
	pmsg.c \
	pproxy.c \
	prop.c \
	qrp.c \
	routing.c \
	rxbuf.c \
	rx.c \
	rx_inflate.c \
	rx_link.c \
	search.c \
	search_xml.c \
	settings.c \
	sha1.c \
	share.c \
	shell.c \
	sockets.c \
	sq.c \
	tiger.c \
	tigertree.c \
	hashtree.c \
	token.c \
	tx.c \
	tx_deflate.c \
	tx_link.c \
	uploads.c \
	upload_stats.c \
	url.c \
	utf8.c \
	vendors.c \
	verify.c \
	version.c \
	vmsg.c \
	walloc.c \
	whitelist.c \
	zalloc.c \
	zlib_util.c

SRCLIST = \
	$(GUI_GTK2) \
	$(GUI_GTK1) \
	$(GUI_COMMON) \
	$(CORE)

OBJLIST = \
	fileinfo_gui2.o \
	gnet_stats_gui2.o \
	monitor_cb2.o \
	monitor_gui2.o \
	nodes_cb2.o \
	nodes_gui2.o \
	search_cb2.o \
	search_gui2.o \
	search_stats_gui2.o \
	uploads_gui2.o \
	upload_stats_gui2.o \
	fileinfo_gui.o \
	gnet_stats_gui.o \
	monitor_cb.o \
	monitor_gui.o \
	nodes_cb.o \
	nodes_gui.o \
	search_cb.o \
	search_gui.o \
	search_stats_gui.o \
	uploads_gui.o \
	upload_stats_gui.o \
	callbacks.o \
	downloads_cb.o \
	downloads_gui.o \
	filter.o \
	filter_cb.o \
	filter_gui.o \
	gnet_stats_gui_common.o \
	gtkcolumnchooser.o \
	gtk-missing.o \
	gui.o \
	gui_property.o \
	main_cb.o \
	main_gui.o \
	nodes_gui_common.o \
	search_gui_common.o \
	settings_cb.o \
	settings_gui.o \
	statusbar_gui.o \
	uploads_cb.o \
	uploads_gui_common.o \
	upload_stats_cb.o \
	adns.o \
	alive.o \
	atoms.o \
	ban.o \
	base32.o \
	base64.o \
	bg.o \
	bsched.o \
	clock.o \
	cobs.o \
	common.o \
	cq.o \
	crc.o \
	dmesh.o \
	downloads.o \
	eval.o \
	event.o \
	extensions.o \
	file.o \
	fileinfo.o \
	fuzzy.o \
	getline.o \
	ggep.o \
	ggep_type.o \
	glib-missing.o \
	gmsg.o \
	gnet_property.o \
	gnet_stats.o \
	guid.o \
	gwcache.o \
	hcache.o \
	header.o \
	hostiles.o \
	hosts.o \
	http.o \
	huge.o \
	icon.o \
	idtable.o \
	ignore.o \
	inet.o \
	inputevt.o \
	ioheader.o \
	main.o \
	matching.o \
	misc.o \
	move.o \
	mq.o \
	namesize.o \
	nodes.o \
	parq.o \
	pcache.o \
	pmsg.o \
	pproxy.o \
	prop.o \
	qrp.o \
	routing.o \
	rxbuf.o \
	rx.o \
	rx_inflate.o \
	rx_link.o \
	search.o \
	search_xml.o \
	settings.o \
	sha1.o \
	share.o \
	shell.o \
	sockets.o \
	sq.o \
	tiger.o \
	tigertree.o \
	hashtree.o \
	token.o \
	tx.o \
	tx_deflate.o \
	tx_link.o \
	uploads.o \
	upload_stats.o \
	url.o \
	utf8.o \
	vendors.o \
	verify.o \
	version.o \
	vmsg.o \
	walloc.o \
	whitelist.o \
	zalloc.o \
	zlib_util.o 

SRC = $(GUI_GLADE_SRC) $(SRCLIST)
OBJ = $(GUI_GLADE_OBJ) $(OBJLIST)

# Those extra flags are expected to be user-defined
CFLAGS = -I$(TOP) $(GTK_CFLAGS) $(XML2_CFLAGS)
DPFLAGS = -I$(TOP) $(GTK_CFLAGS) $(XML2_CFLAGS)
LDFLAGS = $(GTK_LDFLAGS) $(XML2_LDFLAGS)

depend:: ../mkdep

../mkdep:
	@echo "You have to run Configure in $(TOP) first."; exit 1

depend::
	($(SED) '/^# DO NOT DELETE/q' Makefile && \
	$(MKDEP) $(SOURCES) | \
	$(SED) -e 's:/usr/lib[^ ]*::g; s:$(USRINC)[^ ]*::g; ' \
	-e '/: / b print' -e 'H; d; n; : print' -e 'x; s/\\\n//g' \
	-e 's/  */ /g; s/ :/:/;' -e '/: *$$/d' \
	) > Makefile.new
	cp Makefile Makefile.bak
	cp Makefile.new Makefile
	$(RM) Makefile.new

gtk-gnutella:  getdate.c

local_realclean::
	$(RM)  getdate.c

all:: gtk-gnutella

local_realclean::
	$(RM) gtk-gnutella

gtk-gnutella:  $(OBJ) getdate.o
	$(RM) $@
	if test -f $@; then $(MV) $@ $@~; else exit 0; fi
	$(CC) -o $@  $(OBJ) getdate.o $(JLDFLAGS) $(LIBS)

local_install:: gtk-gnutella
	case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(BINDIR) || \
	$(INSTALLDIR) $(INSTALL_PREFIX)$(BINDIR)); \
	$(INSTALL) -c -s -m 555  gtk-gnutella $(INSTALL_PREFIX)$(BINDIR)

local_deinstall::
	$(RM) $(INSTALL_PREFIX)$(BINDIR)/gtk-gnutella

local_install.man:: gtk-gnutella.man
	case '${MFLAGS}' in *[i]*) set +e;; esac;		\
	(set -x; test -d $(INSTALL_PREFIX)$(MANSRC) || \
	$(INSTALLDIR) $(INSTALL_PREFIX)$(MANSRC)); \
	$(INSTALL) -c -m 444 gtk-gnutella.man $(INSTALL_PREFIX)$(MANSRC)/gtk-gnutella.$(L)

local_deinstall.man::
	$(RM) $(INSTALL_PREFIX)$(MANSRC)/gtk-gnutella.$(L)

#Glade generates:
#interface-glade[12].c interface-glade[12].h
#support-glade[12].c support-glade[12].h

#Depending on whether we compile for Gtk 1.2 or Gtk 2, the ones the others
#will be linked and included. This can be tested by checking if USE_GTK2
#is defined in the sourcecode files.
#We let glade directly handle the callbacks.[ch] files so we can do without
#any postprocessing of the glade output.

glade_files:
	$(GLADE) --write-source $(GLADEFILE)

properties:
	autogen gui_props.ag
	autogen gnet_props.ag

########################################################################
# Common rules for all Makefiles -- do not edit

emptyrule::

clean: local_clean
realclean: local_realclean
clobber: local_clobber

local_clean::
	$(RM) core *~ *.o

local_realclean:: local_clean

local_clobber:: local_realclean
	$(RM) Makefile config.sh

install: local_install
install.man: maybe_install.man
deinstall: local_deinstall
deinstall.man: maybe_deinstall.man

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
	else touch $@; exit 0; fi

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

