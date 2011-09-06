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
V=${V:${#VMajor}}

[ "${V:0:1}" == "." ] && V=${V:1} && VMinor=${V%%[.-]*}
V=${V:${#VMinor}}

[ "${V:0:1}" == "." ] && V=${V:1} && VPatch=${V%%-*} && V=${V:${#VPatch}} || VPatch=0

VRev=${V:1}

