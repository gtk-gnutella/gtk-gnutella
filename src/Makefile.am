## Process this file with automake to produce Makefile.in

INCLUDES = \
	@GTK_CFLAGS@

bin_PROGRAMS = gtk-gnutella

# interface.h must come before any .c files that include it so that it is built.
gtk_gnutella_SOURCES = \
	interface.c interface.h \
	gnutella.h \
	misc.c \
	config.c \
	md5.c \
	sockets.c \
	nodes.c \
	hosts.c \
	routing.c \
	search.c search.h \
	filter.c filter.h \
	downloads.c \
	share.c \
	uploads.c \
	main.c \
	gui.c \
	support.c support.h \
	matching.c matching.h \
	callbacks.c callbacks.h \
	dialog-filters.c dialog-filters.h

gtk_gnutella_LDADD = @GTK_LIBS@

GLADE_WARNING1 = "Warning: gtk-gnutella.glade is newer than glade-built files and"
GLADE_WARNING2 = "  \"glade --write-source\" failed.  To ignore any changes to"
GLADE_WARNING3 = "  gtk-gnutella.glade, cd to the src directory, and run"
GLADE_WARNING4 = "  touch interface-glade.c interface-glade.h support.h support.c"


interface-glade.h interface-glade.c support.h support.c: ../gtk-gnutella.glade
	@echo glade --write-source ../gtk-gnutella.glade
	@glade --write-source ../gtk-gnutella.glade || (echo $(GLADE_WARNING1);echo $(GLADE_WARNING2);echo $(GLADE_WARNING3);echo $(GLADE_WARNING4))

interface.h interface.c: interface-glade.c interface-glade.h extern.tcl
	./extern.tcl 
