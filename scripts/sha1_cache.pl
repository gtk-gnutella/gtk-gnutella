# feed this into perl
	eval 'exec perl -S $0 ${1+"$@"}'
		if $running_under_some_shell;

#
# $Id$
#
# Purpose:
#
#	Create a list of files and their SHA1 sums, filesizes and
#       modification times. This list can be used with gtk-gnutella.
#	Just copy or append it to ~/.gtk-gnutella/sha1_cache but
#	make sure gtk-gnutella is not running at the same time. This
#	is especially useful if you want to add a large amount of
#	files to your shared collection. gtk-gnutella has to throttle
#	SHA-1 calculation to prevent long stalls. Thus, this script
#       will be faster and you can off-load the calculation to a
#	different machine or use it when gtk-gnutella is not running.
#
# Example:
#
#       Let's assume you want to share *all* files under /my_shared_files:
#
#	$ cd /my_shared_files
#	$ find . -type f -print0 | xargs -0 sha1_cache.pl > ~/tmp/filelist
#
#       Terminate gtk-gnutella if it's currently running
#
#	$ cat ~/tmp/filelist >> ~/.gtk-gnutella/sha1_cache
#
#	Restart gtk-gnutella and add "/my_shared_files" to your shared
#	directories under "Preferences->Uploads" and click on "Rescan".
#	The blue SHA-1 icon should not show up since all SHA-1 hashes
#	are already known.
#
# Caveats:
#
#	Filenames should not contain any control characters especially
#	not newline characters '\n'. Normal whitespace character are
#       fine.
#

use strict;

(my $me = $0) =~ s|.*/(.*)|$1|;

use Digest::SHA1;
use Convert::Base32;

die "Usage: $me file_1 ... file_n\n" unless @ARGV;

my $cwd = `pwd`;
chomp($cwd);

die "$me: can't compute current directory\n" unless $cwd =~ m|^/|;

foreach my $file (@ARGV) {
	my $path = $file;
	$path = "$cwd/$file" unless $file =~ m|^/|;

	# Normalize the filename by removing unnecessary "/." and "//" sub strings.
	1 while $path =~ s,/[./]?/,/,;

	# Transform "/foo/../" into "/"
	1 while $path =~ s,/[^/]+/\.\./,/,;

	unless (-f $file) {
		warn "$me: skipping non-plain file $file\n";
		next;
	}

	my ($size, $mtime) = (stat(_))[7,9];

	unless (open(FILE, $file)) {
		warn "$me: can't open $file: $!\n";
		next;
	}

	my $digest = digest_fd(\*FILE);
	my $sha1 = uc(encode_base32($digest));
	printf "%s\t%s\t%s\t%s\n", $sha1, $size, $mtime, $path;
}

sub digest_fd {
	my ($fd) = @_;
	my $ctx = Digest::SHA1->new;
	binmode $fd;
	$ctx->addfile($fd);
	return $ctx->digest;
}

