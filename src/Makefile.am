## Process this file with automake to produce Makefile.in

INCLUDES = \
	@GTK_CFLAGS@

bin_PROGRAMS = gtk_gnutella

gtk_gnutella_SOURCES = \
	gnutella.h \
	misc.c \
	config.c \
	md5.c \
	sockets.c \
	nodes.c \
	hosts.c \
	routing.c \
	search.c \
	downloads.c \
	share.c \
	uploads.c \
	main.c \
	gui.c \
	support.c support.h \
	interface.c interface.h \
	callbacks.c callbacks.h

gtk_gnutella_LDADD = @GTK_LIBS@

