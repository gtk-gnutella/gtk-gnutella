#!/usr/bin/perl
	eval 'exec perl5 -S $0 ${1+"$@"}'
		if $running_under_some_shell;

#
# $Id$
#
# Copyright (c) 2003, Raphael Manfredi
#
# Fix copyright of source files, in place, by extending the year range
# if needed for lines bearing the copyright of active developers.
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
#      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#----------------------------------------------------------------------
#

my @DEVS = (
	"Raphael Manfredi",
	"Jeroen Asselman",
);

my $COPYRIGHT = "Copyright \\(c\\)";
$^I = '';

my $year = 1900 + (localtime(time))[5];

while (<>) {
	my $found = 0;
	if (/$COPYRIGHT/o) {
		foreach my $dev (@DEVS) {
			$found++ if /$dev/;
			last if $found;
		}
	}
	if ($found) {
		if (/$COPYRIGHT (\d+),/o) {
			s/^(.*?$COPYRIGHT \d+),/$1-$year,/o if $year > $1;
		} elsif (/$COPYRIGHT \d+-(\d+),/o) {
			s/^(.*?$COPYRIGHT \d+)-\d+,/$1-$year,/o if $year > $1;
		}
	}
	print;
}

