#! /bin/sh

# $Id$

# The following two options should be set in FireFox/Mozilla.
# Enter "about:config" in the address bar.
# Right click and create a new string under the name
# "network.protocol-handler.app.magnet".  Set the value to the
# full path to this script.  Also create a new boolean called
# "network.protocol-handler.external.magnet" and set it to true.
# This script should have execute permissions.  Ie, chmod +x.

# Make sure that there is only one argument and that it starts
# either with "magnet:?" or "http://".

scheme=
case "$1" in
'http://'*)	scheme='http';;
'magnet:?'*)	scheme='magnet';;
*)
esac

if [ $# != 1 ] || [ "X$scheme" = X ]; then
   echo "Usage: ${0##*/} magnet:?[...]" >&2
   exit 1
fi

# Select a default configuration directory.  FireFox/Mozilla can be
# run with alternate exports to over-ride behaviour in this script.
GTK_GNUTELLA_DIR=${GTK_GNUTELLA_DIR-$HOME/.gtk-gnutella}
export GTK_GNUTELLA_DIR

# Don't do anything if GTKG is not running.
gtk-gnutella --ping || {
   echo 'gtk-gnutella is not running.' >&2
   exit 1
}

# Special characters in the URL must not be parsed as quotes or escapes.
url="`printf '%s' "$1" |sed 's,",%22,g' |sed "s,',%27,g" |sed 's,\\\\,%5c,g'`"

# Send a shell command to download the magnet URL.
cat <<EOF | exec gtk-gnutella --shell
intr
download add "$url"
EOF

