## Process this file with automake to produce Makefile.in

SUBDIRS = src
EXTRA_DIST = gtk-gnutella.spec	\
	debian/README.debian		\
	debian/changelog			\
	debian/control				\
	debian/copyright			\
	debian/dirs					\
	debian/gtk-gnutella.1		\
	debian/menu					\
	debian/rules				\
	debian/substvars

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

dist-hook:
	if test -d pixmaps; then \
	  mkdir $(distdir)/pixmaps; \
	  for pixmap in pixmaps/*; do \
	    if test -f $$pixmap; then \
	      cp -p $$pixmap $(distdir)/pixmaps; \
	    fi \
	  done \
	fi

build-glade:
	cd src; $(MAKE) glade_files
