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

SUBDIRS = intl po src

EXTRA_GTK2 = \
	src/monitor_gui2.c \
	src/monitor_cb2.c \
	src/nodes_gui2.c \
	src/nodes_cb2.c \
	src/nodes_cb2.h\
	src/search_gui2.c \
	src/search_cb2.c \
	src/search_cb2.h \
	src/uploads_gui2.c \
	src/upload_stats_gui2.c \
	src/gnet_stats_gui2.c \
	src/search_stats_gui2.c \
	src/interface-glade2.c \
	src/interface-glade2.h \
	src/support-glade2.c \
	src/support-glade2.h


EXTRA_SHELL = \
	src/shell.c \
	src/shell.h

EXTRA_DIST = gtk-gnutella.spec	\
	gwcache.boot \
	debian/README.debian		\
	debian/changelog			\
	debian/control				\
	debian/copyright			\
	debian/dirs					\
	debian/gtk-gnutella.1		\
	debian/menu					\
	debian/rules				\
	debian/substvars			\
	$(EXTRA_GTK2) \
	$(EXTRA_SHELL)

install-data-local:
	@$(NORMAL_INSTALL)
	if test -d $(srcdir)/pixmaps; then \
	  $(mkinstalldirs) $(DESTDIR)$(pkgdatadir)/pixmaps; \
	  for pixmap in $(srcdir)/pixmaps/*; do \
	    if test -f $$pixmap; then \
	      $(INSTALL_DATA) $$pixmap $(DESTDIR)$(pkgdatadir)/pixmaps; \
	    fi \
	  done \
	fi
	$(INSTALL_DATA) $(srcdir)/gwcache.boot $(DESTDIR)$(pkgdatadir)/

dist-hook:
	if test -d pixmaps; then \
	  mkdir $(distdir)/pixmaps; \
	  for pixmap in pixmaps/*; do \
	    if test -f $$pixmap; then \
	      cp -p $$pixmap $(distdir)/pixmaps; \
	    fi \
	  done \
	fi

glade_files:
	$(MAKE) -C src glade_files

properties:
	$(MAKE) -C src properties
