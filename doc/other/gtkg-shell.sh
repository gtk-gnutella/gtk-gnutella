#!/bin/sh
# Copyright (c) 2004 Christian Biere <christianbiere@gmx.de>
#
# $Id$
#
# Usage: gtkg-shell PORT
#
# Uses telnet to connect to a GTKG remote shell on localhost using the
# auth cookie from $GTK_GNUTELLA_DIR/auth_cookie.
#
# This script read from /dev/tty, so you cannot pipe anything through this.

usage() {
  printf 'Usage: gtkg-shell PORT\n'
  exit 1;
}

if [ $# -ne 1 ]; then
  usage
fi

host='localhost'
port="$1"

if [ "${port}" -lt 1 ] || [ "${port}" -gt 65535 ]; then
  printf 'Invalid port value: "%s"' "${port}"
  exit 1
fi

if [ X"${GTK_GNUTELLA_DIR}" = X ]; then
  GTK_GNUTELLA_DIR="${HOME}/.gtk-gnutella"
fi

if [ ! -e "${GTK_GNUTELLA_DIR}" ]; then
  printf 'No such file or directory: "%s"\n' "${GTK_GNUTELLA_DIR}"
  exit 1
fi
if [ ! -d "${GTK_GNUTELLA_DIR}" ]; then
  printf '"%s" is not a directory\n' "${GTK_GNUTELLA_DIR}"
  exit 1
fi


cookie_file="${GTK_GNUTELLA_DIR}/auth_cookie"
if [ ! -e "${cookie_file}" ]; then
  printf 'No such file or directory: "%s"\n' "${cookie_file}"
  exit 1
fi
if [ ! -f "${cookie_file}" ]; then
  printf '"%s" is not a regular file\n' "${cookie_file}"
  exit 1
fi

cookie=''
read cookie < "${cookie_file}"
if [ X"${cookie}" = X ]; then
  printf 'Could not read cookie from "%s"\n' "${cookie_file}"
  exit 1
fi

{
  cat <<EOF # Hide the cookie from the command line
HELO $cookie
EOF

  while :; do {
    cmd=''
    read cmd </dev/tty
    if [ ${?} -ne 0 ]; then
      echo EOF >/dev/stderr
      exit 1
    fi
    printf '%s\n' "${cmd}"
  } done
} | {
  telnet "${host}" "${port}"
  kill -HUP ${$}
}

exit
