#!/bin/sh

# Can be sourced to set two variables:
#
# Vrev, the git version number.
# DATE, the ISO date of the HEAD commit.
#
# Otherwise, when executed it prints the full version number.
#
# If there is a version file (included in release tarballs) at the top of
# the sources, it will be used when "git describe" fails or there is no .git
# repository available.

DIR=scripts

if test -d $DIR; then TOP=.;
elif test -d ../$DIR; then TOP=..;
elif test -d ../../$DIR; then TOP=../..;
elif test -d ../../../$DIR; then TOP=../../..;
elif test -d ../../../../$DIR; then TOP=../../../..;
else
	echo "Can't find the $DIR directory."; exit 1
fi

# Use -d to dump defined variables to stdout
case "$1" in
-d) dump=true;;
esac

# Build reasonable default
file=$TOP/src/gtk-gnutella.h

version=`grep "define GTA_VERSION" $file | head -n1 | awk '{ print $3 }'`
subversion=`grep "define GTA_SUBVERSION" $file | head -n1 | awk '{ print $3 }'`
patchlevel=`grep "define GTA_PATCHLEVEL" $file | head -n1 | awk '{ print $3 }'`
revchar=`grep "define GTA_REVCHAR" $file | head -n1 | awk '{ print $3 }'`
revchar=`echo $revchar | sed -e 's/"//g'`

DEF_VER=$version.$subversion.$patchlevel$revchar

LF='
'
if test -d $TOP/.git && git describe >/dev/null 2>&1 &&
	VN=`git describe --match "v[0-9]*" --abbrev=4 HEAD 2>/dev/null` &&
	case "$VN" in
	*$LF*) exit 1 ;;
	v[0-9]*)
		git update-index -q --refresh
		test -z "`git diff-index --name-only HEAD --`" ||
		VN="$VN-dirty" ;;
	esac
then
	case "$revchar" in
	'') DATE=;;
	*)
		DATE=`git show --format="%ai" HEAD 2>/dev/null | head -1 | cut -f1 -d ' '`
		;;
	esac
elif test -s $TOP/version; then
	VN=`cat $TOP/version`
else
	VN="$DEF_VER"
fi

VN=`echo $VN | sed -e s/^v//`
V=$VN

VMajor=`echo $V | sed -e 's/^\([0-9]*\).*/\1/'`
V=`echo $V | sed -e s/^$VMajor//`

VMinor=`echo $V | sed -e 's/^\.\([0-9]*\).*/\1/'`
V=`echo $V | sed -e s/^.$VMinor//`
case "$V" in
.*)
	VPatch=`echo $V | sed -e 's/^\.\([0-9]*\).*/\1/'`
	V=`echo $V | sed -e s/^.$VPatch//`
	;;
*) VPatch=0;;
esac

# Strip "u" or "b" in the version, if present
case "$V" in
[a-z]*) VRev=`echo $V | sed -e s/^[a-z]//`;;
*) VRev=$V;;
esac

VRev=`echo $VRev | sed -e s/^-//`

# Dump defined variables when -d given
case "$dump" in
'') ;;
*)
	cat <<EOD
DEF_VER=$DEF_VER
LAST=$LAST
DATE=$DATE
VN=$VN
VMajor=$VMajor
VMinor=$VMinor
VPatch=$VPatch
VRev=$VRev
version=$version
subversion=$subversion
patchlevel=$patchlevel
revchar=$revchar
EOD
	;;
esac

# Output version number
echo $VN
