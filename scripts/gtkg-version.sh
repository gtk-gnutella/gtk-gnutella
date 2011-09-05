#!/bin/bash
D=`dirname $0`

source ${D}/git-version.sh

echo "#define GTA_VERSION $VMajor"
echo "#define GTA_SUBVERSION $VMinor"
echo "#define GTA_PATCHLEVEL $VPatch"
echo "#define GTA_BUILD \"$VRev\""

