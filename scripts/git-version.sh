#!/bin/sh

DEF_VER=v0.97

LF='
'

# First see if there is a version file (included in release tarballs),
# then try git-describe, then default.
if test -f version
then
	VN=$(cat version) || VN="$DEF_VER"
elif git describe >/dev/null 2>&1 &&
	VN=$(git describe --match "v[0-9]*" --abbrev=4 HEAD 2>/dev/null) &&
	case "$VN" in
	*$LF*) (exit 1) ;;
	v[0-9]*)
		git update-index -q --refresh
		test -z "$(git diff-index --name-only HEAD --)" ||
		VN="$VN-dirty" ;;
	esac
then
	VN="$VN"
else
	VN="$DEF_VER"
fi

VN=$(expr "$VN" : v*'\(.*\)')

echo $VN
V=$VN

VMajor=${V%%.*}
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
