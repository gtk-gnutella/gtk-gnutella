#!/usr/bin/perl
#
# ciabot -- Mail a CVS log message to a given address, for the purposes of CIA
#
# Loosely based on cvslog by Russ Allbery <rra@stanford.edu>
# Copyright 1998  Board of Trustees, Leland Stanford Jr. University
#
# Copyright 2001, 2003  Petr Baudis <pasky@ucw.cz>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2, as published by the
# Free Software Foundation.
#
# This program is designed to run from the loginfo CVS administration file. It
# takes a log message, massaging it and mailing it to the address given below.
#
# Its record in the loginfo file should look like:
#
#       ALL /usr/bin/perl $CVSROOT/CVSROOT/ciabot.pl %s $USER
#

use strict;
use vars qw ($project $from_email $dest_email $max_lines $sync_delay
		$commit_template $branch_template $trimmed_template);




### Configuration

# Project name (as known to CIA).
$project = 'gtk-gnutella';

# The from address in the generated mails.
$from_email = 'guruz_irc_admin@guruz.de';

# Mail all reports to this address.
$dest_email = 'commits@picogui.org';

# The maximal number of lines the log message should have.
$max_lines = 6;

# Number of seconds to wait for possible concurrent instances. CVS calls up
# this script for each involved directory separately and this is the sync
# delay. 5s looks as a safe value, but feel free to increase if you are running
# this on a slower (or overloaded) machine or if you have really a lot of
# directories.
$sync_delay = 5;

# The template string describing how the commit message should look like.
# Expansions:
#  %user%   - who committed it
#  %tag%    - expands to the branch tag template ($branch_template), if the
#             commit hapenned in a branch
#  %module% - the module where the commit happenned
#  %path%   - the longest common path of all the committed files
#  %file%   - the file name or number of files (and possibly number of dirs)
#  %trimmed%- a notice about the log message being trimmed, if it is
#             ($trimmed_template)
#  %logmsg% - the log message
$commit_template = '{green}%user%{normal}%tag% * {light blue}%module%{normal}/%path% (%file%): %trimmed%%logmsg%';

# The template string describing how the branch tag name should look like.
# Expansions:
#  %tag%    - the tag name
$branch_template = ' {yellow}%tag%{normal}';

# The template string describing how the trimming notice should look like.
# Expansions:
#  none
$trimmed_template = '(log message trimmed)';




### The code itself

use vars qw ($user $module $tag @files $logmsg);

my @dir; # This array stores all the affected directories
my @ci;  # This array is mapped to the @dir array and contains files affected
         # in each directory
my $logmsg_lines;



### Input data loading


# These arguments are from %s; first the relative path in the repository
# and then the list of files modified.

@files = split (' ', $ARGV[0]);
$dir[0] = shift @files or die "$0: no directory specified\n";
$ci[0] = "@files" or die "$0: no files specified\n";

$module = $dir[0]; $module =~ s#/.*##;


# Figure out who is doing the update.

$user = $ARGV[1];


# Parse stdin (what's interesting is the tag and log message)

while (<STDIN>) {
  $tag = $1 if /^\s*Tag: ([a-zA-Z0-9_-]+)/;
  last if /^Log Message/;
}

$logmsg_lines = 0;
while (<STDIN>) {
  next unless ($_ and $_ ne "\n" and $_ ne "\r\n");
  $logmsg_lines++;
  last if ($logmsg_lines > $max_lines);
  $logmsg .= $_;
}



### Sync between the multiple instances potentially being ran simultanously

my $sum; # _VERY_ simple hash of the log message. It is really weak, but I'm
         # lazy and it's really sorta exceptional to even get more commits
         # running simultanously anyway.
map { $sum += ord $_ } split(//, $logmsg);

my $syncfile; # Name of the file used for syncing
$syncfile = "/tmp/cvscia.$project.$module.$sum";


if (-f $syncfile) {
  # The synchronization file for this file already exists, so we are not the
  # first ones. So let's just dump what we know and exit.

  open(FF, ">>$syncfile") or die "aieee... can't log, can't log! $syncfile blocked!";
  print FF "$ci[0]!@!$dir[0]\n";
  close(FF);
  exit;

} else {
  # We are the first one! Thus, we'll fork, exit the original instance, and
  # wait a bit with the new one. Then we'll grab what the others collected and
  # go on.

  # We don't need to care about permissions since all the instances of the one
  # commit will obviously live as the same user.

  system("touch $syncfile");

  exit if (fork);
  sleep($sync_delay);

  open(FF, $syncfile);
  my ($i) = 1;
  while (<FF>) {
    chomp;
    ($ci[$i], $dir[$i]) = split(/!@!/);
    $i++;
  }
  close(FF);

  unlink($syncfile);
}



### Send out the mail


# Open our mail program

open (MAIL, '| /usr/lib/sendmail -t -oi -oem')
    or die "$0: cannot fork sendmail: $!\n";


# The mail header

print MAIL <<EOM;
From: $from_email
To: $dest_email
Content-type: text/plain
Subject: Announce $project

EOM


# Compute the longest common path, plus make up the file and directory count

my (@commondir, $files, $file, $i);

for ($i = 0; $i < @dir; $i++) {
  my ($dir) = $dir[$i];

  my (@cd) = split(/\//, $dir);
  for (my $j = 0; $j < @cd; $j++) {
    if (defined $commondir[$j] and $commondir[$j] ne $cd[$j]) {
      splice(@commondir, $j);
      last;
    }
    if ($i == 0) {
      $commondir[$j] = $cd[$j];
    } elsif (not defined $commondir[$j]) {
      last;
    }
  }

  my (@cii) = split(/ /, $ci[$i]);
  $files += @cii;
  $file = $cii[0] if ($files == 1);
}

die "No files!" unless ($files > 0);

shift(@commondir); # Throw away the module name.


# Send out the mail body


my ($path) = join('/', @commondir);

my ($filestr); # the file name or file count or whatever
if ($files > 1) {
  $filestr = $files . ' files';
  if ($i > 1) {
    $filestr .= ' in ' . $i . ' dirs';
  }
} else {
  $filestr = $file;
}

my ($trimmedstr); # the trimmed string, if any at all
if ($logmsg_lines > $max_lines) {
  $trimmedstr = $trimmed_template;
} else {
  $trimmedstr = '';
}

my ($tagstr); # the branch name, if any at all
if ($tag) {
  $tagstr = $branch_template;
  $tagstr =~ s/\%tag\%/$tag/g;
} else {
  $tagstr = '';
}

$logmsg = "\n" . $logmsg if ($logmsg_lines > 1);

my ($bodystr) = $commit_template; # the message to be sent
$bodystr =~ s/\%user\%/$user/g;
$bodystr =~ s/\%tag\%/$tagstr/g;
$bodystr =~ s/\%module\%/$module/g;
$bodystr =~ s/\%path\%/$path/g;
$bodystr =~ s/\%file\%/$filestr/g;
$bodystr =~ s/\%trimmed\%/$trimmedstr/g;
$bodystr =~ s/\%logmsg\%/$logmsg/g;

print MAIL $bodystr."\n";


# Close the mail

close MAIL;
die "$0: sendmail exit status " . $? >> 8 . "\n" unless ($? == 0);
