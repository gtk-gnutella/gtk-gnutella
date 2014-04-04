#!/usr/bin/perl
	eval 'exec perl5 -S $0 ${1+"$@"}'
		if $running_under_some_shell;

#
# Copyright (c) 2014, Raphael Manfredi
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
#
# This program takes a list of variable definitions and their associated
# English translations and generates the associated C data structures so
# that we can symbolically handle the constants and yet obtain human-readable
# translation of these constants.
#
# The input is made up of tabulated names and strings, such as:
#
#		CONSTANT	"Description of the constant"
#
# The generation of the C data structures is controlled by a set of textual
# definitions that make up the parameters of this script:
#
# Count: FOO			-- name of additional enum representing count of items
# Prefix: MSG_			-- prefix to add to C constants
# Lowercase: yes		-- Whether constant symbolic names should be lower-cased
# I18N: yes				-- Whether to make descriptions translatable
# Enum: constant_enum	-- Name of the C enum for symbolic constants
# Enum-Init: 0			-- Value of the first enum symbol
# Symbolic: sym_name	-- Name of C string array for symbolic names
# Description: sym_desc	-- Name of C array containing textual descriptions
# Enum-File: foo.h		-- Name of C file for enum definitions
# Enum-to-Symbolic: foo		-- Routine name to translate enum to symbolic text
# Enum-to-Description: foo	-- Routine name to translate enum to English text
# Enum-to-Code: foo.c		-- Filename where translation routine are generated
# Enum-to-Header: foo.h		-- Filename for translation routine declarations
# Protection-Prefix: xxx	-- String to prepend to #ifndef for header file
#
# Assuming the constants are held in "file.lst" and the parameters of this
# script in "file.dsc", then the generation process can be launched by
# running:
#
#	enum-msg.pl file.lst file.dsc
#
# By default nothing is generated if the generated files are more recent than
# the "file.lst" file, but generation can be forced by using '-f'.
#

use strict;

my $KEY_COUNT				= "count";
my $KEY_PREFIX				= "prefix";
my $KEY_LOWERCASE			= "lowercase";
my $KEY_I18N				= "i18n";
my $KEY_ENUM				= "enum";
my $KEY_ENUM_INIT			= "enum-init";
my $KEY_SYMBOLIC			= "symbolic";
my $KEY_DESCRIPTION			= "description";
my $KEY_ENUM_FILE			= "enum-file";
my $KEY_ENUM_TO_SYMBOLIC	= "enum-to-symbolic";
my $KEY_ENUM_TO_DESCRIPTION	= "enum-to-description";
my $KEY_ENUM_TO_CODE		= "enum-to-code";
my $KEY_ENUM_TO_HEADER		= "enum-to-header";
my $KEY_PROTECTION_PREFIX	= "protection-prefix";

(my $me = $0) =~ s|.*/(.*)|$1|;

use Getopt::Std;

use vars qw/$opt_h/;

&usage unless getopts("h");
&usage if $opt_h;
&usage unless 2 == @ARGV;

sub usage {
	die <<EOM;
Usage: $me [-h] file.lst file.dsc
  -h : print this message and exit
EOM
}


my ($input, $desc) = @ARGV;

my %desc;
my (@sym, @text);
my (%files, %hprotect);

load_desc($desc, \%desc);
load_input($input, \@sym, \@text);

my $enum		= $desc{$KEY_ENUM};
my $init		= $desc{$KEY_ENUM_INIT};
my $fname		= $desc{$KEY_ENUM_FILE};
my $prefix		= $desc{$KEY_PREFIX};
my $count		= $desc{$KEY_COUNT};
my $protect		= $desc{$KEY_PROTECTION_PREFIX};
my $symbolic	= $desc{$KEY_SYMBOLIC};
my $etext		= $desc{$KEY_DESCRIPTION};
my $sym_cfile	= $desc{$KEY_ENUM_TO_CODE};
my $sym_hfile	= $desc{$KEY_ENUM_TO_HEADER};
my $e2sym		= $desc{$KEY_ENUM_TO_SYMBOLIC};
my $e2txt		= $desc{$KEY_ENUM_TO_DESCRIPTION};
my $lowercase	= $desc{$KEY_LOWERCASE} =~ /yes/i;
my $i18n		= $desc{$KEY_I18N} =~ /yes/i;

die "$me: missing $KEY_ENUM_TO_CODE key in $desc to handle $KEY_SYMBOLIC\n"
	if defined $symbolic && !defined $sym_cfile;

die "$me: missing $KEY_ENUM_TO_HEADER key in $desc to handle $KEY_SYMBOLIC\n"
	if defined $symbolic && !defined $sym_hfile;

#
# Generation of the enum {} definition.
#

if (defined $fname && defined $enum) {
	my $fd = create_file($fname);
	my $n = scalar @sym;
	print $fd <<EOC;
/*
 * Enum count: $n
 */
typedef enum {
EOC
	my $done = 0;
	foreach my $e (@sym) {
		print $fd ",\n" if $done++;
		print $fd "\t$prefix$e";
		print $fd " = $init" if 1 == $done && defined $init;
	}
	if (defined $count) {
		print $fd ",\n\n\t$prefix$count\n";
	} else {
		print $fd "\n";
	}
	print $fd <<EOC;
} $enum;

EOC
}

#
# Generation of the symbolic enum code array.
#

if (defined $sym_cfile) {
	my $fdc = create_file($sym_cfile);
	print $fdc <<EOC;
#include "common.h"

EOC
	print $fdc <<EOC if defined $sym_hfile;
#include "$sym_hfile"
EOC
	print $fdc <<EOC;

#include "lib/override.h"

EOC
}

if (defined $sym_cfile && defined $symbolic) {
	my $fdc = create_file($sym_cfile);
	my $fdh = create_file($sym_hfile) if defined $sym_hfile;
	die "$me: key $KEY_ENUM missing in description file $desc"
		unless defined $enum;
	print $fdh <<EOH if defined $fdh && defined $e2sym;
const char *$e2sym($enum x);

EOH
	print $fdc <<EOC;
/*
 * Symbolic descriptions for $enum.
 */
static const char *$symbolic\[] = {
EOC
	foreach my $e (@sym) {
		my $s = $lowercase ? lc($e) : $e;
		print $fdc "\t\"$s\",\n";
	}
	print $fdc <<EOC;
};

EOC
	print $fdc <<EOC if defined $e2sym;
/**
 * \@return the symbolic description of the enum value, NULL if out of bounds.
 */
const char *
$e2sym($enum x)
{
	g_return_val_if_fail(
		UNSIGNED(x) < G_N_ELEMENTS($symbolic), NULL);

	return $symbolic\[x];
}

EOC
}

#
# Generation of the English description array.
#

if (defined $sym_cfile && defined $etext) {
	my $fdc = create_file($sym_cfile);
	my $fdh = create_file($sym_hfile) if defined $sym_hfile;
	die "$me: key $KEY_ENUM missing in description file $desc"
		unless defined $enum;
	print $fdh <<EOH if defined $fdh && defined $e2txt;
const char *$e2txt($enum x);

EOH
	print $fdc <<EOC;
/*
 * English descriptions for $enum.
 */
static const char *$etext\[] = {
EOC
	foreach my $t (@text) {
		my $d = $i18n ? "N_(\"$t\")" : "\"$t\"";
		print $fdc "\t$d,\n";
	}
	print $fdc <<EOC;
};

EOC
	print $fdc <<EOC if defined $e2txt;
/**
 * \@return the English description of the enum value, NULL if out of bounds.
 */
const char *
$e2txt($enum x)
{
	g_return_val_if_fail(
		UNSIGNED(x) < G_N_ELEMENTS($etext), NULL);

	return $etext\[x];
}

EOC
}

# Close all files requiring protection
while (my ($f, $psym) =  each %hprotect) {
	my $fd = $files{$f};
	print $fd "#endif /* $psym */\n\n";
}

# Close all the opened files
while (my ($f, $fd) =  each %files) {
	print $fd "/* vi: set ts=4 sw=4 cindent: */\n";
	close $fd;
}

# Create file, if not already done in this session
# Returns the opened file descriptor
sub create_file {
	my ($name) = @_;
	return $files{$name} if defined $files{$name};
	# Unlinking file to break filesystem hard links to the file
	unlink($name);
	my $fd;
	open(my $fd, ">$name") || die "$me: cannot create file $name: $!\n";
	$files{$name} = $fd;
	my $time = scalar localtime;
	print $fd <<EOC;
/*
 * Generated on $time by $me -- DO NOT EDIT
 *
 * Command: $0 $input $desc
 */

EOC
	if ($name =~ /\.h$/) {
		my $symbol = $name;
		$symbol =~ s/[.-]/_/g;
		my $psym = "_${protect}_${symbol}_";
		$hprotect{$name} = $psym;
		print $fd <<EOC;
#ifndef $psym
#define $psym

EOC
	}
	return $fd;
}

# Load description: what we need to generate and where
sub load_desc {
	my ($file, $href) = @_;
	open(DESC, $file) || die "$me: cannot open $file: $!\n";
	local $_, $.;
	while (<DESC>) {
		chomp;
		next if /^#/ || /^\s*$/;
		my ($key, $value) = /^([-\w]+):\s*(.*)/;
		unless (defined $key) {
			warn "$me: skipping bad line #$. '$_' in $file\n";
			next;
		}
		$href->{lc($key)} = $value;
	}
	close DESC;
}

# Load input: the symbols to define and their English description
sub load_input {
	my ($file, $sref, $tref) = @_;
	open(INPUT, $file) || die "$me: cannot open $file: $!\n";
	local $_, $.;
	while (<INPUT>) {
		chomp;
		next if /^#/ || /^\s*$/;
		my ($sym, $text) = /^(\w+)\s*"(.*)"/;
		unless (defined $sym) {
			# Handle continuations: symbol followed by text on next line
			($sym) = /^(\w+)/;
			if (defined $sym) {
				$_ = <INPUT>;
				($text) = /^\s+"(.*)"/;		# Continuation must be indented
			}
			if (!defined($sym) || !defined($text)) {
				warn "$me: skipping bad line #$. '$_' in $file\n";
				next;
			}
		}
		push(@$sref, $sym);
		push(@$tref, $text);
	}
	close INPUT;
}

