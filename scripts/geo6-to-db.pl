#! /usr/bin/env perl

#
# $Id$
#
# Copyright (c) 2011, Raphael Manfredi
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

require 'getopt.pl';

&Getopt;

#
# Converts the Geo IPv6 database into a suitable format for GTKG
# From http://www.tcpiputils.com/download/ipv6geodb.csv
#
# 2001:0608:0004::/48,DE,Germany,51.1657,10.4515,"SPACENET SpaceNET AG, Munich"
#
# From http://geolite.maxmind.com/download/geoip/database/GeoIPv6.csv.gz
#
# "2c0f:ff40::", "2c0f:ff80:ffff:ffff:ffff:ffff:ffff:ffff",
#	"58569093352465652911071180633164218368",
#	"58569098502296216338253124213520990207", "ZA", "South Africa"
#

if ($opt_g) {
	print "# From " .
		"http://geolite.maxmind.com/download/geoip/database/GeoIPv6.csv.gz\n";
	print "# Redistributed under the OPEN DATA LICENSE (see GEO_LICENCE)\n";
} else {
	print "# From http://www.tcpiputils.com/download/ipv6geodb.csv\n";
}
print "# Conversion for GTKG generated on ", scalar(gmtime), " GMT\n";

if ($opt_g) {
	while (<>) {
		chomp;
		my @items = map { s/^\s*"//; s/"$//; $_ } split(/,/);
		my $start = $items[0];
		my $end = $items[1];
		my $country = lc($items[4]);
		my $country_name = $items[5];
		my $bits = leading_bits($start, $end);

		next if $country_name eq '';

		print "$start/$bits $country\n";
	}
} else {
	while (<>) {
		chomp;
		my @items = map { s/^"//; s/"$//; $_ } split(/,/);
		my $range = $items[0];
		my $country = lc($items[1]);

		next if $range =~ /^cidr/i;

		print "$range $country\n";
	}
}

sub bits_set {
	my ($value) = @_;
	my $b = 0;
	while ($value & 0x1) {
		$value >>= 1;
		$b++;
	}
	return $b;
};

sub leading_bits {
	my ($start, $end) = @_;
	die unless $start =~ s/::$/:/;
	substr($end, 0, length($start)) = '';
	my $set = 0;
	foreach $b (split(/:/, $end)) {
		$set += bits_set(hex($b));
	}
	return 128 - $set;
}

