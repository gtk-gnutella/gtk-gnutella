%define name gtk-gnutella
%define version 0.17
%define release 1
%define prefix /usr

Summary: Gtk-Gnutella is a GUI based Gnutella Client. It's based upon the original look of Gnutella v0.5.
Name: %{name}
Version: %{version}
Release: %{release}
Group: Applications
Copyright: GPL
Packager: Rickard Osser <ricky@osser.se>
URL: http://gtk-gnutella.sourceforge.net
Source0: http://prdownloads.sourceforge.net/%{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-buildroot
%Description
Gtk-Gnutella is a GUI based Gnutella Client. It's based upon the original
look of Gnutella v0.5.

It's a fully featured Gnutella Client designed to share any type of file
the user wishes to share.

It's a Unix clone, and it needs GTK+ (1.2 or above). Gnome is not needed. It
is currently developed and tested under Linux (Redhat 6). It is known to run
at least on Linux and FreeBSD (on 80x86 machines). It is released under the
GNU Public License (GPL).
%Prep
%setup
%Build
./configure --prefix=%{prefix}
make
%Install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin/
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
make install prefix=$RPM_BUILD_ROOT/usr
cp README $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
cp TODO $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
cp NEWS $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
cp INSTALL $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
cp AUTHORS $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
cp ChangeLog $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
cp COPYING $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}

%clean
rm -rf $RPM_BUILD_ROOT
%files
%defattr(-,root,root)
/usr/bin/gtk-gnutella

%doc README COPYING ChangeLog AUTHORS TODO INSTALL NEWS
