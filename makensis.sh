#!/bin/sh
# Generates the gtk-gnutella installer on Windows

# Season to taste
export MINGW=C:/MinGW
export WD=$MINGW/msys/1.0/bin
export PATH=$PATH:'/c/Program Files/NSIS':$MINGW/lib/gtk/bin

if makensis gtk-gnutella.nsi >makensis.log 2>&1; then
	echo "OK"
else
	echo "FAILED"
fi

