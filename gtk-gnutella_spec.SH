# $Id$

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
: This forces SH files to create target in same directory as SH file.
: This is so that make depend always knows where to find SH derivatives.
case "$0" in
*/*) cd `expr X$0 : 'X\(.*\)/'` ;;
esac
echo "Extracting gtk-gnutella.spec (with variable substitutions)"
: This section of the file will have variable substitutions done on it.
: Move anything that needs config subs from !NO!SUBS! section to !GROK!THIS!.
: Protect any dollar signs and backticks that you do not want interpreted
: by putting a backslash in front.  You may delete these comments.
$spitshell >gtk-gnutella.spec <<!GROK!THIS!
Summary: A GUI-based Gnutella Client
Name: gtk-gnutella
Version: $gtkgversion
!GROK!THIS!

: In the following dollars and backticks do not need the extra backslash.
$spitshell >>gtk-gnutella.spec <<'!NO!SUBS!'
Release: 1
URL: http://sourceforge.net/projects/gtk-gnutella/
Source: %{name}-%{version}.tar.gz
License: GPL
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-root
BuildPreReq: gtk+-devel glib-devel libglade-devel libxml2-devel bison

%description
Gtk-Gnutella is a GUI based Gnutella p2p servent. It's a fully featured  
servent designed to share any type of file.  Gtk-gnutella implements 
compressed gnutella net connections, ultrapeer and leaf nodes and uses 
Passive/Active Remote Queueing (PARQ).

%prep
%setup -q

%build
./Configure -Dprefix=%_prefix -Dbindir=%_bindir -Dprivlib=%_datadir/%name \
	-Dsysman=%_mandir/man1 -Dccflags="-Wall" -Dcc=gcc \
	-Doptimize="-g -O2" -Dyacc="bison -y" -Dgtkversion=1  \
	-Dofficial=true -ders

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%_bindir $RPM_BUILD_ROOT/%_mandir/man1
%{__make} install INSTALL_PREFIX=$RPM_BUILD_ROOT
%{__make} install.man INSTALL_PREFIX=$RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/%_datadir/applications
cp -f gtk-gnutella.desktop \
$RPM_BUILD_ROOT/%_datadir/applications/gtk-gnutella.desktop

mkdir -p $RPM_BUILD_ROOT/%_datadir/pixmaps
cp -f gtk-gnutella.png $RPM_BUILD_ROOT/%_datadir/pixmaps

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,0755)
%{_bindir}/*
%{_datadir}/gtk-gnutella
%{_datadir}/applications/gtk-gnutella.desktop
%{_datadir}/pixmaps/gtk-gnutella.png
%{_datadir}/locale
%{_mandir}/man1

%doc README TODO AUTHORS ChangeLog

%changelog
* Tue Dec 11 2001 Sam Varshavchik <mrsam@courier-mta.com>
- Initial build.

!NO!SUBS!
chmod 755 gtk-gnutella.spec
$eunicefix gtk-gnutella.spec
