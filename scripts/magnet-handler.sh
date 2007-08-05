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
# with "magnet:".

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

# gtk-gnutella may not be installed or local_shell.c might have been
# compiled as a standalone.  Allow some way to over-ride default.

# Don't do anything if GTKG is not running.
gtk-gnutella --ping || exit 1

# Send a shell command to download the magnet URL.
cat <<EOF | exec gtk-gnutella --shell
download add "$1"
EOF

