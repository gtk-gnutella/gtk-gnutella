#
# $Id$
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


if ENABLE_GTK2
INCLUDES = \
	@GTK_GNUTELLA_CFLAGS@ \
	@XML_CFLAGS@
GLADECMD = glade-2
GLADEFILE = gtk2-gnutella.glade
GLADE_UI = \
	interface-glade2.c interface-glade2.h \
	support-glade2.c support-glade2.h
ADDITIONAL_DROPIN = \
	share_gui2.c share_gui.h
gtk_gnutella_LDADD = @GTK_GNUTELLA_LIBS@ -lz @XML_LIBS@
else
INCLUDES = \
	@GTK_CFLAGS@ \
	@XML_CFLAGS@
GLADECMD = glade
GLADEFILE = gtk-gnutella.glade
GLADE_UI = \
	interface-glade1.c interface-glade1.h \
	support-glade1.c support-glade1.h
ADDITIONAL_DROPIN = \
	gtkcolumnchooser.c gtkcolumnchooser.h \
	share_gui.c share_gui.h \
	nodes_gui.c nodes_gui.h nodes_cb.c nodes_cb.h \
	gui_property.c gui_property.h gui_property_priv.h \
	settings_gui.c settings_gui.h settings_cb.c settings_cb.h \
	statusbar_gui.c statusbar_gui.h \
	search_gui.c search_gui.h search_cb.c search_cb.h \
	main_gui.c main_gui.h
gtk_gnutella_LDADD = @GTK_LIBS@ -lz @XML_LIBS@
endif

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
	$(GLADE_UI) \
	$(ADDITIONAL_DROPIN) \
	gnutella.h \
	gnet.h \
	misc.c misc.h \
	prop.c prop.h \
	gnet_property.c gnet_property.h gnet_property_priv.h \
	settings.c settings.h oldconfig.c oldconfig.h \
	sockets.c sockets.h \
	nodes.c nodes.h \
	hosts.c hosts.h \
	pcache.c pcache.h \
	routing.c routing.h \
	search.c search.h search_gui.h \
	search_stats.c search_stats.h search_stats_gui.h \
	downloads.c downloads.h downloads_gui.h \
	share.c share.h \
	uploads.c uploads.h uploads_gui.h \
	upload_stats.c upload_stats.h upload_stats_gui.h \
	main.c \
	gui.c gui.h \
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
	sha1.c sha1.h huge.c huge.h \
	base32.c base32.h \
	utf8.c utf8.h \
	filter.c filter.h filter_cb.c filter_cb.h filter_gui.c filter_gui.h \
	ban.c ban.h \
	qrp.c qrp.h \
	getdate.y getdate.h \
	atoms.c atoms.h \
	extensions.c extensions.h ggep.h \
	dmesh.c dmesh.h \
	http.c http.h \
	version.c version.h \
	alive.c alive.h \
	zalloc.c zalloc.h \
	walloc.c walloc.h

GLADE_WARNING1 = "Warning: gtk-gnutella.glade is newer than glade-built files and"
GLADE_WARNING2 = "  \"glade --write-source\" failed.  To ignore any changes to"
GLADE_WARNING3 = "  gtk-gnutella.glade, cd to the src directory, and run"
GLADE_WARNING4 = "  touch interface-glade.c interface-glade.h support.h support.c"

#
# Glade generates:
#	interface-glade[12].c interface-glade[12].h
#   support-glade[12].c support-glade[12].h
#
# Depending on wether we compile for Gtk 1.2 or Gtk 2, the ones the others
# will be linked and included. This can be tested by checking if USE_GTK2
# is defined in the sourcecode files.
# We let glade directly handle the callbacks.[ch] files so we can do without
# any postprocessing of the glade output.
#

glade_files:
	@echo $(GLADECMD) --write-source ../$(GLADEFILE)
	@$(GLADECMD) --write-source ../$(GLADEFILE) || (echo $(GLADE_WARNING1);echo $(GLADE_WARNING2);echo $(GLADE_WARNING3);echo $(GLADE_WARNING4))

properties:
	autogen gui_props.ag
	autogen gnet_props.ag


