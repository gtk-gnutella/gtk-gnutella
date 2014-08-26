#! /bin/sh

# The purpose is the same as the lndir tool of X11.
# Duplicates the directory structure of DIRECTORY into the current
# working directory with all regular files replaced by symlinks.
# This is useful for compiling without littering the source tree
# with object files and such.

set -e

# Don't overwrite by default
force=''

usage() {
	echo "USAGE: lntool [OPTIONS] [DIRECTORY]";
	echo "OPTIONS:"
	echo "  --force  Force ln to overwrite existing files or links.";
	echo "           Useful when updating an existing tree.";
	exit 1;
}

test $# -gt 0 || usage

while [ $# -gt 0 ]
do
	case "$1" in
	-f|--force)	force='-f'
			;;
	--)		shift
			break
			;;
	*)		break
			;;
	esac
	shift
done

test $# -eq 1 || usage

src="${1%%/}"

case "$src" in
/*|./*)	
	;;
'')	usage
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
	( cd "$dir" && ln -s ${force} "$item" )
done

exit 0

