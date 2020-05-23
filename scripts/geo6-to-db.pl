#! /usr/bin/env perl

#
# $Id$
#
# Copyright (c) 2011, 2018, Raphael Manfredi
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

use strict;

use Getopt::Std;
getopts('dg');

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
# Options:
#   -d : add comments showing how each initial range splits
#   -g : select the GeoIP file format

my $CNT = 8;

if ($'opt_g) {
	print "# From " .
		"http://geolite.maxmind.com/download/geoip/database/GeoIPv6.csv.gz\n";
	print "# Redistributed under the OPEN DATA LICENSE (see GEO_LICENCE)\n";
} else {
	print "# From http://www.tcpiputils.com/download/ipv6geodb.csv\n";
}
print "# Conversion for GTKG generated on ", scalar(gmtime), " GMT\n";

if ($'opt_g) {
	while (<>) {
		chomp;
		my @items = map { s/^\s*"//; s/"$//; $_ } split(/,/);
		my $start = $items[0];
		my $end = $items[1];
		my $country = lc($items[4]);
		my $country_name = $items[5];
		next if $country_name eq '';

		my $start6 = IPv6->make($start);
		my $end6 = IPv6->make($end);
		print "# $start6 -> $end6\n" if $'opt_d;
		print_networks($start6, $end6, $country);
		print "\n" if $'opt_d;
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

# Print network ranges encompassing the IP space between two boundaries
#
# NOTE: This is the same algorithm as the one in geo-to-db.pl, only we handle
# IPv6 address objects here.
sub print_networks {
	my ($ip1, $ip2, $country) = @_;

	my $bits = $ip1->common_leading_bits($ip2);
	my $mask = IPv6->single_bit(128 - $bits);

	if ($bits == 128) {
		die "ip1=$ip1, ip2=$ip2" if $ip1 != $ip2;
		print "$ip1 $country\n";
	} elsif (($ip2 & ($mask - 1)) == $mask - 1) {
		# All the trailing bits of $ip2 are 1s.
		if (0 == ($ip1 & ($mask - 1))) {
			# All the trailing bits in $ip1 are 0s, we're done.
			print "$ip1/$bits $country\n";
		} else {
			# Start filling after the first 1 bit in $ip1
			$mask = IPv6->single_bit(0);
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
		# We know that bits #(128-$bits) in $ip1 and $ip2 differ
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
			print "# invalid range $ip1 - $ip2\n";
		}
	}
}

package IPv6;

# Representation is an array of 8 16-bit words = 128 bits, big-endian format

use overload
	'""'	=> \&to_str,
	"<<"	=> \&lshift,
	">>"	=> \&rshift,
	'&'		=> \&and,
	'|'		=> \&or,
	'~'		=> \&not,
	'=='	=> \&eq,
	'!='	=> \&neq,
	'+'		=> \&plus,
	'-'		=> \&minus;

# Equal operation
sub eq {
	my ($self, $other) = @_;
	$other = IPv6->number($other) unless ref $other;
	for (my $i = 0; $i < $CNT; $i++) {
		return 0 if $self->[$i] != $other->[$i];
	}
	return 1;
}

# Not-equal operation
sub neq {
	my ($self, $other) = @_;
	return !$self->eq($other);
}

# Not operation
sub not {
	my ($self) = @_;
	my $result = IPv6->number(0);
	for (my $i = 0; $i < $CNT; $i++) {
		$result->[$i] = ~$self->[$i];
	}
	return $result;
}

# Or operation
sub or {
	my ($self, $other) = @_;
	$other = IPv6->number($other) unless ref $other;
	my $result = IPv6->number(0);
	for (my $i = 0; $i < $CNT; $i++) {
		$result->[$i] = $self->[$i] | $other->[$i];
	}
	return $result;
}

# And operation
sub and {
	my ($self, $other) = @_;
	$other = IPv6->number($other) unless ref $other;
	my $result = IPv6->number(0);
	for (my $i = 0; $i < $CNT; $i++) {
		$result->[$i] = $self->[$i] & $other->[$i];
	}
	return $result;
}

# Left shift operation by 1, inplace
sub lshift1 {
	my ($self) = @_;
	my $carry = 0;
	for (my $i = $CNT; $i > 0; $i--) {
		my $j = $i - 1;
		my $v = $self->[$j];
		$v <<= 1;
		$v |= 1 if $carry;
		$self->[$j] = $v & 0xffff;
		$carry = 0x10000 == ($v & 0x10000);
	}
}

# Left shift operation by whole chunks of 16-bits
sub lshift16 {
	my ($self, $result, $n) = @_;
	for (my $i = $n; $i < $CNT; $i++) {
		$result->[$i - $n] = $self->[$i];
	}
	for (my $i = 0; $i < $n; $i++) {
		$result->[$CNT - $i] = 0;
	}
}

# Left shift operation
sub lshift {
	my ($self, $n) = @_;
	return $self if 0 == $n;
	my $result = IPv6->number(0);
	return $result if $n >= 128;
	lshift16($self, $result, int($n / 16));
	my $partial = $n % 16;
	for (my $i = 0; $i < $partial; $i++) {
		lshift1($result);
	}
	return $result;
}

# Right shift operation by 1, inplace
sub rshift1 {
	my ($self) = @_;
	my $carry = 0;
	for (my $i = 0; $i < $CNT; $i++) {
		my $v = $self->[$i];
		$v |= 0x10000 if $carry;
		$carry = 0x1 == ($v & 0x1);
		$v >>= 1;
		$self->[$i] = $v;
	}
}

# Right shift operation by whole chunks of 16-bits
sub rshift16 {
	my ($self, $result, $n) = @_;
	for (my $i = $n; $i < $CNT; $i++) {
		$result->[$i] = $self->[$i - $n];
	}
	for (my $i = 0; $i < $n; $i++) {
		$result->[$i] = 0;
	}
}

# Right shift operation
sub rshift {
	my ($self, $n) = @_;
	return $self if 0 == $n;
	my $result = IPv6->number(0);
	return $result if $n >= 128;
	rshift16($self, $result, int($n / 16));
	my $partial = $n % 16;
	for (my $i = 0; $i < $partial; $i++) {
		rshift1($result);
	}
	return $result;
}

# Plus operation
sub plus {
	my ($self, $other) = @_;
	$other = IPv6->number($other) unless ref $other;
	my $result = bless [], ref $self;
	my $carry = 0;
	for (my $i = $CNT; $i > 0; $i--) {
		my $j = $i - 1;
		my $v = $self->[$j] + $other->[$j] + $carry;
		$result->[$j] = $v & 0xffff;
		$carry = $v >= 0x10000 ? 1 : 0;
	}
	return $result;
}

# Minus operation
sub minus {
	my ($self, $other, $swap) = @_;
	$other = IPv6->number($other) unless ref $other;
	my $result = bless [], ref $self;
	my ($a, $b) = ($self, $other);
	($a, $b) = ($other, $self) if $swap;
	my $carry = 0;
	for (my $i = $CNT; $i != 0; $i--) {
		my $j = $i - 1;
		my $v = $a->[$j] - $b->[$j] - $carry;
		if ($v < 0) {
			$carry = 1;
			$v += 65536;
		} else {
			$carry = 0;
		}
		$result->[$j] = $v;
	}
	return $result;
}

# Determines the highest bit set, -1 if value was 0.
sub highest_bit_set {
	my ($n) = @_;
	my $mask = 1 << 31;
	for (my $i = 32; $i > 0; $i--, $mask >>= 1) {
		return $i - 1 if $n & $mask;
	}
	return -1;
}

# Find common leading bits between two IPv6 addresses
sub common_leading_bits {
	my $self = shift;
	my ($other) = @_;
	for (my $i = 0; $i < $CNT; $i++) {
		my $diff = $self->[$i] ^ $other->[$i];
		return $i * 16 + 15 - highest_bit_set($diff) if $diff;
	}
	return 128;
}

# Stringify IPv6 address
sub to_str {
	my $self = shift;
	# Count longest 0 streak
	my $longest_streak = 0;
	my $longest_start = -1;
	my ($streak, $start);
	for (my $i = 0; $i < $CNT; $i++) {
		if (0 == $self->[$i]) {
			if ($streak) {
				$streak++;
			} else {
				$streak = 1;
				$start = $i;
			}
		} else {
			if ($streak > $longest_streak) {
				$longest_streak = $streak;
				$longest_start = $start;
			}
			$streak = 0;
		}
	}
	if ($streak > $longest_streak) {
		$longest_streak = $streak;
		$longest_start = $start;
	}
	my $str;
	my $first = 1;
	for (my $i = 0; $i < $CNT; $i++) {
		if ($i == $longest_start) {
			die if $self->[$i] != 0;
			$str .= "::";
			$i += $longest_streak - 1;	# ++ in the loop above
			$first = 1;
		} else {
			$str .= ":" if !$first;
			$str .= sprintf "%x", $self->[$i];
			$first = 0;
		}
	}
	return $str;
}

# Creation routine, from number
sub number {
	my $self = bless [], shift;
	my ($n) = @_;			# Assume 32-bit max
	$self->[$CNT - 1] = $n % 65536;
	$self->[$CNT - 2] = int($n / 65536);
	return $self;
}

# Creation routine, setting said bit
# Bit 0 is the rightmost bit.
sub single_bit {
	my $self = bless [], shift;
	my ($bit) = @_;
	$self->[0, $CNT-1] = 0;
	my $q = $CNT - int($bit / 16) - 1;
	$self->[$q] = 1 << ($bit % 16);
	return $self;
}

# Creation routine from IPv6 string representation
sub make {
	my $self = bless [], shift;
	my ($addr) = @_;
	if ($addr =~ /::/) {
		my ($lead) = ($addr =~ /^(.*)::/);
		my ($tail) = ($addr =~ /::(.*)$/);
		my @q1 = map { hex($_) } split(/:/, $lead);
		my @q2;
		# Check for IPv4 after ::
		if ($tail =~ /\./) {
			my @ip = split(/\./, $tail);
			die if @ip != 4;
			$q2[0] = ($ip[0] << 8) | $ip[1];
			$q2[1] = ($ip[2] << 8) | $ip[3];
		} else {
			@q2 = map { hex($_) } split(/:/, $tail);
		}
		my $missing = $CNT - (@q1 + @q2);
		@$self = @q1;
		for (my $i = 0; $i < $missing; $i++) {
			push(@$self, 0);
		}
		push(@$self, @q2);
	} else {
		@$self = map { hex($_) } split(/:/, $addr);
	}
	die if @$self != $CNT;
	return $self;
};

# vi: set sw=4 ts=4:
