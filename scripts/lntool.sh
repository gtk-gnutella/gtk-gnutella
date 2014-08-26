#! /bin/sh

# The purpose is the same as the lndir tool of X11.
# Duplicates the directory structure of DIRECTORY into the current
# working directory with all regular files replaced by symlinks.
# This is useful for compiling without littering the source tree
# with object files and such.

set -e

test $# -eq 1 || { echo "USAGE: lntool [DIRECTORY]"; exit 1; }

src="${1%%/}";
case "$src" in
/*|./*)	
	;;
*) 	src="./$src"
	;;
esac

test -d "$src" || { echo "ERROR: Argument is not a directory"; exit 1; }

find "$src" -type f -print | while read item
do
	relpath="${item#$src/}"
	case "$relpath" in
	*/*)	dir="${relpath%/*}"
		;;
	*)	dir='.'
		;;
	esac
	mkdir -p "$dir"
	( cd "$dir" && ln -s "$item" )
done

exit 0

