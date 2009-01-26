#! /bin/sh
#
# $Id$
#
# Requires:
#
#   bitter - see contrib/bitter in gtk-gnutella's SVN repository
#   stat - The stat tool provided by FreeBSD, NetBSD or GNU coreutils.
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
#	$ find . -type f -print0 | xargs -0 sha1_cache.sh > ~/tmp/filelist
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

if [ $# -lt 1 ]; then
  echo 'sha1_cache.sh FILE_1 ... FILE_n' >&2
  exit 1
fi

# Detect the variant of "stat"; unfortunately there is no standard
# for this. It is needed to get the filesize and timestamp of a file.
stat=$(stat --version 2>/dev/null | sed -n 's,^.*\(coreutils\).*$,\1,p')

stat /dev/null >/dev/null 2>&1 || {
  echo 'ERROR: The stat tool seems unusable.' >&2
  exit 1
}

# Current working directory; for converting relative pathnames
path=$(pwd) || exit
case "${path}" in
  /*)
      ;;
  *)  echo 'ERROR: Could not detect absolute path.' >&2
      exit 1
      ;;
esac

while [ $# -gt 0 ]; do

  file=$1
  shift

  # Convert relative pathnames to absolute pathnames.
  case "${file}" in
    /*)
     ;;
    *) file="${path}/${file}"
     ;;
  esac

  # Normalize the filename by removing unnecessary "/." and "//" sub strings.
  file_norm=${file}
  while :; do
    file=${file_norm}
    file_norm=$(printf '%s' "${file_norm}" | sed 's,/[./]/,/,g; s,//,/,g')
    if [ "${file}" = "${file_norm}" ]; then
      break
    fi
  done

  # Transform "/foo/../" into "/"
  file_norm=${file}
  while :; do
    file=${file_norm}
    file_norm=$( printf '%s' "${file_norm}" | sed 's,/[^/]*/[.][.]/,/,')
    echo "${file_norm}" >&2
    if [ "${file}" = "${file_norm}" ]; then
      break
    fi
  done

  if [ ! -f "${file}" ]; then
     printf 'Not a regular file: "%s"\n' "${file}" >&2
     continue
  fi

  sha1=$(bitter -S < "${file}") || continue
  sha1=$(printf '%s' "${sha1}" | sed 's,^urn:sha1:,,') || continue

  if [ "${stat}" = 'coreutils' ]; then
    size=$(stat -c '%s' -- "${file}") || continue
    stamp=$(stat -c '%Y' -- "${file}") || continue
  else
    size=$(stat -f '%z' -- "${file}") || continue
    stamp=$(stat -f '%m' -- "${file}") || continue
  fi

  printf '%s\t%s\t%s\t%s\n' "${sha1}" "${size}" "${stamp}" "${file}" || break

done

exit

