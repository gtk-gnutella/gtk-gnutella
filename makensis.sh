#!/bin/sh
# Generates the gtk-gnutella installer on Windows

# Season to taste
export MINGW=C:/MinGW
export WD=$MINGW/msys/1.0/bin
if test -d '/c/Program Files/NSIS'; then
	NDIR='/c/Program Files/NSIS'
elif test -d '/c/Program Files (x86)/NSIS'; then
	NDIR='/c/Program Files (x86)/NSIS'
else
	echo "Where is NSIS installed?"
	NDIR=/c
fi
export PATH=$PATH:$NDIR:$MINGW/lib/gtk/bin

if makensis gtk-gnutella.nsi >makensis.log 2>&1; then
	echo "OK"
else
	echo "FAILED"
fi

