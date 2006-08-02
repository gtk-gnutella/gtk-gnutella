# feed this into perl
	eval 'exec perl -S $0 ${1+"$@"}'
		if $running_under_some_shell;

#
# $Id: sha1_cache.sh 11402 2006-08-01 22:27:44Z cbiere $
#
# Purpose:
#
#	Create a list of files and their SHA1 sums, filesizes and
#       modification times. This list can be used with Gtk-Gnutella.
#	Just copy or append it to ~/.gtk-gnutella/sha1_cache but
#	make sure Gtk-Gnutella is not running at the same time. This
#	is especially useful if you want to add a large amount of
#	files to your shared collection. Gtk-Gnutella has to throttle
#	SHA-1 calculation to prevent long stalls. Thus, this script
#       will be faster and you can off-load the calculation to a
#	different machine or use it when Gtk-Gnutella is not running.
#
# Example:
#
#       Let's assume you want to share *all* files under /my_shared_files:
#
#	$ cd /my_shared_files
#	$ find . -type f -print0 | xargs -0 sha1_cache.pl > ~/tmp/filelist
#
#       Terminate Gtk-Gnutella if it's currently running
#
#	$ cat ~/tmp/filelist >> ~/.gtk-gnutella/sha1_cache
#
#	Restart Gtk-Gnutella and add "/my_shared_files" to your shared
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

foreach my $file (@ARGV) {
	# Normalize the filename by removing unnecessary "/." and "//" sub strings.
	1 while $file =~ s,/[./],/,;

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
	printf "%s\t%s\t%s\t%s\n", $sha1, $size, $mtime, $file;
}

sub digest_fd {
	my ($fd) = @_;
	my $ctx = Digest::SHA1->new;
	binmode $fd;
	$ctx->addfile($fd);
	return $ctx->digest;
}

