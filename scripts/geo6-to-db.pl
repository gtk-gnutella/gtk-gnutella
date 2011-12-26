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

#
# Converts the Geo IPv6 database into a suitable format for GTKG
# From http://www.tcpiputils.com/download/ipv6geodb.csv
#
# 2001:0608:0004::/48,DE,Germany,51.1657,10.4515,"SPACENET SpaceNET AG, Munich"
#

print "# From http://www.tcpiputils.com/download/ipv6geodb.csv\n";
print "# Conversion for GTKG generated on ", scalar(gmtime), " GMT\n";

while (<>) {
	chomp;
	my @items = map { s/^"//; s/"$//; $_ } split(/,/);
	my $range = $items[0];
	my $country = lc($items[1]);

	next if $range =~ /^cidr/i;

	print "$range $country\n";
}

