## Process this file with automake to produce Makefile.in

INCLUDES = \
	@GTK_CFLAGS@

bin_PROGRAMS = gtk-gnutella
CLEANFILES = interface-glade.c interface-glade.h *.bak

# interface.h must come before any .c files that include it so that it is built.
gtk_gnutella_SOURCES = \
	autodownload.h autodownload.c \
	interface.c interface.h \
	gnutella.h \
	misc.c misc.h \
	config.c appconfig.h \
	sockets.c sockets.h \
	nodes.c nodes.h \
	hosts.c hosts.h \
	routing.c routing.h \
	search.c search.h \
	filter.c filter.h \
	downloads.c downloads.h \
	share.c share.h \
	uploads.c uploads.h \
	main.c \
	gui.c gui.h \
	support.c support.h \
	matching.c matching.h \
	callbacks.c callbacks.h \
	dialog-filters.c dialog-filters.h \
	getline.c getline.h \
	header.c header.h

gtk_gnutella_LDADD = @GTK_LIBS@

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

