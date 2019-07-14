#! /usr/bin/env perl

#
# Copyright (c) 2019 Raphael Manfredi
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

use strict;

#
# Usage:
#
#	geolite-to-db.pl OUTPUT GeoLite2-Country-Blocks-IPvX.csv
#
# to generate the text database in OUTPUT, in a format suitable for
# gtk-gnutella consumption based on the CIDR country block description
# held in the CSV file (second argument).
#
# File GeoLite2-Country-Locations-en.csv contains locations:
#
#	174982,en,AS,Asia,AM,Armenia,0
#
# 174982 is the code used in other files to reference this location, and
# AM is the 2-letter ISO country code.
#
# File GeoLite2-Country-Blocks-IPv4.csv maps a CIDR range to a location.
# File GeoLite2-Country-Blocks-IPv6.csv maps a CIDR range to a location.
#
# Both files have entries such as:
#
# 	1.1.64.0/18,1861060,1861060,,0,0
#
# or
#
#	2001:470:5:4000::/50,6252001,6252001,,0,0
#
# What matters to us are the first two fields: the IP address and the location,
# but sometimes the location is missing in which case we have to use the 3rd
# field to get the region (for Europe apparently).
#
# There are also the cases of anonymizing proxies and satellite providers, which
# are identified by the last two fields (boolean values) in that order.
#

my $LOC = "GeoLite2-Country-Locations-en.csv";
my %LOC;

load_locations($LOC, \%LOC);
my $output = shift @ARGV;
open(OUTPUT, ">$output") || die "$0: cannot create output $output: $!\n";

print OUTPUT "# From GeoLite2 Free Downloadable Databases\n";
print OUTPUT "# See https://dev.maxmind.com/geoip/geoip2/geolite2/\n";
print OUTPUT "# Conversion for GTKG generated on ", scalar(gmtime), " GMT\n";

while (<>) {
	chomp;
	next if 1 == $.;			# First line is field information
	my @f = split(/,/);
	my $range = $f[0];
	my $cc = $f[1];
	$cc = $f[2] unless length $cc;

	my $country = $LOC{$cc};
	unless (length $country) {
		$country = "a1" if $f[4];	# Anonymizing proxies
		$country = "a2" if $f[5];	# Satellite providers
	}
	unless (length $country) {
		warn "$0: unknown country code $cc in $_\n";
		next;
	}

	print OUTPUT "$range $country\n";
}

close OUTPUT;

# Load locations into supplied map
sub load_locations {
	my ($loc, $map) = @_;
	local (*LOC, $_);
	open(LOC, $loc) || die "$0: can't open $loc: $!\n";
	while (<LOC>) {
		my @f = split(/,/);
		my $country = $f[4];
		$country = $f[2] if 0 == length $country;	# Use region if no country
		$map->{$f[0]} = lc($country);
	}
	close LOC;
}

# vi: set sw=4 ts=4:
