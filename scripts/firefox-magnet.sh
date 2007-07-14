#!/bin/sh

# $Id$

# The following two options should be set in FireFox/Mozilla.
# Enter "about:config" in the address bar.
# Right click and create a new string under the name
# "network.protocol-handler.app.magnet".  Set the value to the
# full path to this script.  Also create a new boolean called
# "network.protocol-handler.external.magnet" and set it to true.
# This script should have execute permissions.  Ie, chmod +x.

# Select a default configuration directory.  FireFox/Mozilla can be
# run with alternate exports to over-ride behaviour in this script.
if [ "$GTK_GNUTELLA_DIR" = "" ]
then
export GTK_GNUTELLA_DIR=$HOME/.gtk-gnutella
fi

# Select default for gtk-gnutella executable.
if [ "$GTKG" = "" ]
then

GTKG=gtk-gnutella

if [ `uname -s` = "Linux" ]
then

# Obtain the PID of the process.
GTKG_PID=`pgrep -f "gnutella" | tail -n 1`

GTKG=/proc/$GTKG_PID/exe
fi

fi


# Don't do anything if GTKG is not running.
$GTKG --ping || exit

# Send a shell command to download the magnet URL.
# Fixme: How to escape spaces and shell escapces, etc.
echo download add \"$1\" | $GTKG --shell
