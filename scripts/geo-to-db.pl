#! /usr/bin/env perl

#
# $Id$
#
# Copyright (c) 2004, Raphael Manfredi
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
# Converts the Geo IP database into a GTKG network format
# From http://www.maxmind.com/app/geoip_country
#
# "2.0.0.0","2.6.190.55","33554432","33996343","ZA","South Africa"
#

use Getopt::Std;
getopts('c');

print "# From http://www.maxmind.com/app/geoip_country\n";
print "# Redistributed under the OPEN DATA LICENSE (see GEO_LICENCE)\n";
print "# Conversion for GTKG generated on ", scalar(gmtime), " GMT\n";

while (<>) {
	chomp;
	my @items = map { s/^"//; s/"$//; $_ } split(/,/);
	my $first = $items[0];
	my $last = $items[1];
	my $country = lc($items[4]);

	my $ip1 = ip_to_int($first);
	my $ip2 = ip_to_int($last);

	if ($ip1 > $ip2) {
		warn "Inverted range '$first - $last $country' -- skipping line $.\n";
		next;
	}

	my $bits = find_common_leading($ip1, $ip2);
	if ($bits == 0) {
		warn "Invalid range '$first - $last $country' -- skipping line $.\n";
		next;
	}

	if ($opt_c) {
		# Compact format
		print "$first - $last $country\n";
	} else {
		print "# $first - $last\n";
		print_networks($ip1, $ip2, $country);
		print "\n";
	}
}

# Converts IP in doted decimal to a 32-bit integer
sub ip_to_int {
	my ($a) = @_;
	my @a = split(/\./, $a);
	return ($a[0] << 24) | ($a[1] << 16) | ($a[2] << 8) | $a[3];
}

# Converts IP from 32-bit integer to doted decimal
sub int_to_ip {
	my ($a) = @_;
	my @a;
	for (my $i = 3; $i >= 0; $i--) {
		$a[$i] = $a & 0xff;
		$a >>= 8;
	}

	return join('.', @a);
}

# Find common leading bits between two IP addresses
sub find_common_leading {
	my ($ip1, $ip2) = @_;
	my $n;

	for ($n = 1, my $mask = 0x80000000; $n <= 32; $n++, $mask |= ($mask >> 1)) {
		return $n - 1 if ($ip1 & $mask) != ($ip2 & $mask);
	}

	return $n - 1;
}

# Print network ranges encompassing the IP space between two boundaries
sub print_networks {
	my ($ip1, $ip2, $country) = @_;

	my $bits = find_common_leading($ip1, $ip2);
	my $mask = 1 << (32 - $bits);

	if ($bits == 32) {
		die "ip1=$ip1, ip2=$ip2" if $ip1 != $ip2;
		print int_to_ip($ip1), " $country\n";
	} elsif (($ip2 & ($mask - 1)) == $mask - 1) {
		# All the trailing bits of $ip2 are 1s.
		if (0 == ($ip1 & ($mask - 1))) {
			# All the trailing bits in $ip1 are 0s, we're done.
			print int_to_ip($ip1), "/$bits $country\n";
		} else {
			# Start filling after the first 1 bit in $ip1
			$mask = 1;
			while (0 == ($ip1 & $mask)) {
				$mask <<= 1;
			}
			my $to = ($mask - 1) | $ip1;

			# First cover from $ip1 to $to, then the trailing range.
			print_networks($ip1, $to, $country);
			print_networks($to + 1, $ip2, $country);
		}
	} else {
		# We can't cover the full range.
		# We know that bits #(32-$bits) in $ip1 and $ip2 differ
		$mask >>= 1;					# First bit that differs
		if (($ip1 & $mask) == 0) {
			# Bit is 0 in $ip1, then we know it must be set in $ip2, and we
			# can cover the range between $ip1 and $ip2 with that bit reset to
			# 0 and all the trailing bits of $ip2 set.

			die if 0 == ($ip2 & $mask);
			my $to = $ip2 & ~$mask;		# Reset that bit in $ip2
			$to |= $mask - 1;			# And set the trailing bits to 1
			print_networks($ip1, $to, $country);

			# Now cover the trailing range, starting where we left off

			$ip1 = $to + 1;				# First range not covered yet
			print_networks($ip1, $ip2, $country);
		} else {
			# Bit is 1 in $ip1, it is 0 in $ip2.
			# This means an invalid IP range was specified
			die if 1 == ($ip2 & $mask);
			print "# invalid range ",
				int_to_ip($ip1), " - ", int_to_ip($ip2), "\n";
		}
	}
}
