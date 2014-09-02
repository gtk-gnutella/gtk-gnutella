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
	if [ "x$1" != 'x' ]
	then echo "ERROR: $1" >&2
	fi
	cat << EOM >&2
USAGE: lntool.sh [OPTIONS] SOURCE [DESTINATION]
       SOURCE is the directory tree to copy.
       DESTINATION is optional and the leaf directory of SOURCE by default.
EXAMPLES:
       lntool.sh /example/test -> copies tree to ./test
       lntool.sh /example/test blah -> copies tree to ./blah
OPTIONS:
       --force | -f  Force ln to overwrite existing files or links.
                     Useful when updating an existing tree.
       --help | -h   Display this information.
EOM
	exit 1;
}

trimslash() {
	arg="$1"
	while [ "/" != "$arg" ] && [ "x${arg}" != "x${arg%/}" ]
	do
		arg="${arg%/}"
	done
	echo "$arg"
}

pathify() {
	arg="$(trimslash "$1")"
	case "$arg" in
	/*|./*|'')	echo "$arg";;
	*) 		echo "./$arg";;
	esac
}

test $# -gt 0 || usage

while [ $# -gt 0 ]
do
	case "$1" in
	--)		shift
			break
			;;
	-h|--help)	usage	
			;;
	-f|--force)	force='-f'
			;;
	-*)		usage 'Unknown option'
			;;
	*)		break
			;;
	esac
	shift
done

test $# -gt 0 || usage 'Missing argument'
test $# -lt 3 || usage 'ERROR: Too many arguments'

src="$(pathify "$1")"
shift

test -d "$src" || usage 'Argument is not a directory'

if [ $# -eq 0 ]
then	dst="${src##*/}"
else	dst="$1"
fi

dst="$(pathify "$dst")"

mkdir -p "$dst"
cd "$dst"

find "$src" ! -type d -print | while read item
do
	relpath="${item#$src/}"
	case "$relpath" in
	*/*)	dir="${relpath%/*}"
		;;
	*)	dir='.'
		;;
	esac
	mkdir -p "$dir"
	(	
		cd "$dir"
		ln -s ${force} "$item"
	)
done

exit 0

