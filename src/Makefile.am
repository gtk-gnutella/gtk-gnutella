#
# Copyright (c) 2001-2002, Raphael Manfredi
#
#----------------------------------------------------------------------
# This file is part of gtk-gnutella.
#
#  gtk-gnutella is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  gtk-gnutella is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with gtk-gnutella; if not, write to the Free Software
#  Foundation, Inc.:
#      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#----------------------------------------------------------------------
#

## Process this file with automake to produce Makefile.in


INCLUDES = \
	@GTK_CFLAGS@ \
	@XML_CFLAGS@

bin_PROGRAMS = gtk-gnutella
CLEANFILES = interface-glade.c interface-glade.h *.bak

XML_STORE_FILES = search_xml.c search_xml.h

if ENABLE_XML_STORE
XML_STORE = $(XML_STORE_FILES)
else
XML_STORE =
endif

# interface.h must come before any .c files that include it so that it is built.
gtk_gnutella_SOURCES = \
	$(XML_STORE) \
	interface.c interface.h \
	gnutella.h \
	misc.c misc.h \
	config.c appconfig.h \
	sockets.c sockets.h \
	nodes.c nodes.h \
	hosts.c hosts.h \
	pcache.c pcache.h \
	routing.c routing.h \
	search.c search.h \
	search_stats.c search_stats.h \
	downloads.c downloads.h \
	share.c share.h \
	uploads.c uploads.h \
	upload_stats.c upload_stats.h \
	main.c \
	gui.c gui.h \
	support.c support.h \
	matching.c matching.h \
	callbacks.c callbacks.h \
	getline.c getline.h \
	header.c header.h \
	url.c url.h \
	pmsg.c pmsg.h \
	gmsg.c gmsg.h \
	cq.c cq.h \
	mq.c mq.h \
	sq.c sq.h \
	bsched.c bsched.h \
	tx.c tx.h \
	tx_link.c tx_link.h \
	tx_deflate.c tx_deflate.h \
	rxbuf.c rxbuf.h \
	rx.c rx.h \
	rx_link.c rx_link.h \
	rx_inflate.c rx_inflate.h \
	zlib_util.c zlib_util.h \
	gtk-missing.c gtk-missing.h \
	gtkcolumnchooser.c gtkcolumnchooser.h \
	sha1.c sha1.h huge.c huge.h \
	base32.c base32.h \
	utf8.c utf8.h \
	filter.c filter.h filter_cb.c filter_cb.h filter_gui.c filter_gui.h\
	ban.c ban.h \
	qrp.c qrp.h \
	getdate.y getdate.h \
	atoms.c atoms.h \
	extensions.c extensions.h ggep.h \
	dmesh.c dmesh.h \
	http.c http.h \
	version.c version.h \
	alive.c alive.h

gtk_gnutella_LDADD = @GTK_LIBS@ -lz @XML_LIBS@

GLADE_WARNING1 = "Warning: gtk-gnutella.glade is newer than glade-built files and"
GLADE_WARNING2 = "  \"glade --write-source\" failed.  To ignore any changes to"
GLADE_WARNING3 = "  gtk-gnutella.glade, cd to the src directory, and run"
GLADE_WARNING4 = "  touch interface-glade.c interface-glade.h support.h support.c"

#
# Glade generates:
#	interface-glade.c interface-glade.h
#   callbacks-glade.c callbacks-glade.h (which we don't care about)
#   support.c support.h
#
# We then generate interface.h and interface.h via ./extern.tcl
#

glade_files:
	@echo glade --write-source ../gtk-gnutella.glade
	@glade --write-source ../gtk-gnutella.glade || (echo $(GLADE_WARNING1);echo $(GLADE_WARNING2);echo $(GLADE_WARNING3);echo $(GLADE_WARNING4))
	rm -f callbacks-glade.c callbacks-glade.h
	./extern.tcl 

