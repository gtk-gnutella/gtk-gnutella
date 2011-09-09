#!/bin/sh

DIR=scripts

if test -d $DIR; then TOP=.;
elif test -d ../$DIR; then TOP=..;
elif test -d ../../$DIR; then TOP=../..;
elif test -d ../../../$DIR; then TOP=../../..;
elif test -d ../../../../$DIR; then TOP=../../../..;
else
	echo "Can't find the $DIR directory."; exit 1
fi

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

# First see if there is a version file (included in release tarballs),
# then try git-describe, then default.
if test -s $TOP/version
then
	VN=`cat version` || VN="$DEF_VER"
elif git describe >/dev/null 2>&1 &&
	VN=`git describe --match "v[0-9]*" --abbrev=4 HEAD 2>/dev/null` &&
	case "$VN" in
	*$LF*) exit 1 ;;
	v[0-9]*)
		git update-index -q --refresh
		test -z "`git diff-index --name-only HEAD --`" ||
		VN="$VN-dirty" ;;
	esac
then
	VN="$VN"
else
	VN="$DEF_VER"
fi

VN=`echo $VN | sed -e s/^v//`

echo $VN
V=$VN

VMajor=`echo $V | sed -e 's/^\([0-9]*\).*/\1/'`
V=`echo $V | sed -e s/^$VMajor//`

VMinor=`echo $V | sed -e 's/^\.\([0-9]*\).*/\1/'`
V=`echo $V | sed -e s/^.$VMinor//`
case "$V" in
.*) VPatch=`echo $V | sed -e 's/^\.\([0-9]*\).*/\1/'`;;
*) VPatch=0;;
esac

# Strip "u" or "b" in the version, if present
case "$V" in
[a-z]*) VRev=`echo $V | sed -e s/^[a-z]//`;;
*) VRev=$V;;
esac

VRev=`echo $VRev | sed -e s/^-//`
