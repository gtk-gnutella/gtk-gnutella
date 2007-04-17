#! /bin/sh
#
# $Id$
#
# This script generates a list of magnets of all currently shared files using
# the SHA-1 cache of gtk-gnutella. The host itself is added as exact source.
# The filename will be URL-encoded. Thus this script may be useful to create a
# mirror of host.

default_dir="${HOME}/.gtk-gnutella"
dir=${GTK_GNUTELLA_DIR-$default_dir}

config="${dir}/config_gnet"
sha1_cache="${dir}/sha1_cache"

port=$(sed -n 's,^listen_port[\t ]*=[\t ]*\([0-9]*\).*$,\1,p' < "${config}")

host=$(sed -n 's,^server_hostname[\t ]*=[\t ]"\([^"]*\)".*$,\1,p' < "${config}")
if [ "x$host" = x ]; then
  host=$(sed -n 's,^local_ip[\t ]*=[\t ]"\([^"]*\)".*$,\1,p' < "${config}")
fi

export host port

awk '
function urlencode(x) {
  gsub("%", "%25", x)

  gsub("\\x01", "%01", x)
  gsub("\\x02", "%02", x)
  gsub("\\x03", "%03", x)
  gsub("\\x04", "%04", x)
  gsub("\\x05", "%05", x)
  gsub("\\x06", "%06", x)
  gsub("\\x07", "%07", x)
  gsub("\\x08", "%08", x)
  gsub("\\x09", "%09", x)
  gsub("\\x0a", "%0a", x)
  gsub("\\x0b", "%0b", x)
  gsub("\\x0c", "%0c", x)
  gsub("\\x0d", "%0d", x)
  gsub("\\x0e", "%0e", x)
  gsub("\\x0f", "%0f", x)
  gsub("\\x10", "%10", x)
  gsub("\\x11", "%11", x)
  gsub("\\x12", "%12", x)
  gsub("\\x13", "%13", x)
  gsub("\\x14", "%14", x)
  gsub("\\x15", "%15", x)
  gsub("\\x16", "%16", x)
  gsub("\\x17", "%17", x)
  gsub("\\x18", "%18", x)
  gsub("\\x19", "%19", x)
  gsub("\\x1a", "%1a", x)
  gsub("\\x1b", "%1b", x)
  gsub("\\\\",  "%1c", x)
  gsub("\\x1d", "%1d", x)
  gsub("\\x1e", "%1e", x)
  gsub("\\x1f", "%1f", x)
  gsub("\\x20", "%20", x)
  gsub("\\x21", "%21", x)
  gsub("\\x22", "%22", x)
  gsub("\\x23", "%23", x)
  gsub("[$]",   "%24", x)

  gsub("&",     "%26", x)
  gsub("\\x27", "%27", x)
  gsub("[*]",   "%2a", x)
  gsub("[+]",   "%2b", x)

  gsub("[<]",   "%3c", x)
  gsub("[>]",   "%3e", x)
  gsub("[?]",   "%3f", x)
  gsub("[@]",   "%40", x)

  gsub("[`]", "%60", x)
  gsub("\\x7f", "%7f", x)

  gsub("\\x80", "%80", x)
  gsub("\\x81", "%81", x)
  gsub("\\x82", "%82", x)
  gsub("\\x83", "%83", x)
  gsub("\\x84", "%84", x)
  gsub("\\x85", "%85", x)
  gsub("\\x86", "%86", x)
  gsub("\\x87", "%87", x)
  gsub("\\x88", "%88", x)
  gsub("\\x89", "%89", x)
  gsub("\\x8a", "%8a", x)
  gsub("\\x8b", "%8b", x)
  gsub("\\x8c", "%8c", x)
  gsub("\\x8d", "%8d", x)
  gsub("\\x8e", "%8e", x)
  gsub("\\x8f", "%8f", x)

  gsub("\\x90", "%90", x)
  gsub("\\x91", "%91", x)
  gsub("\\x92", "%92", x)
  gsub("\\x93", "%93", x)
  gsub("\\x94", "%94", x)
  gsub("\\x95", "%95", x)
  gsub("\\x96", "%96", x)
  gsub("\\x97", "%97", x)
  gsub("\\x98", "%98", x)
  gsub("\\x99", "%99", x)
  gsub("\\x9a", "%9a", x)
  gsub("\\x9b", "%9b", x)
  gsub("\\x9c", "%9c", x)
  gsub("\\x9d", "%9d", x)
  gsub("\\x9e", "%9e", x)
  gsub("\\x9f", "%9f", x)

  gsub("\\xa0", "%a0", x)
  gsub("\\xa1", "%a1", x)
  gsub("\\xa2", "%a2", x)
  gsub("\\xa3", "%a3", x)
  gsub("\\xa4", "%a4", x)
  gsub("\\xa5", "%a5", x)
  gsub("\\xa6", "%a6", x)
  gsub("\\xa7", "%a7", x)
  gsub("\\xa8", "%a8", x)
  gsub("\\xa9", "%a9", x)
  gsub("\\xaa", "%aa", x)
  gsub("\\xab", "%ab", x)
  gsub("\\xac", "%ac", x)
  gsub("\\xad", "%ad", x)
  gsub("\\xae", "%ae", x)
  gsub("\\xaf", "%af", x)

  gsub("\\xb0", "%b0", x)
  gsub("\\xb1", "%b1", x)
  gsub("\\xb2", "%b2", x)
  gsub("\\xb3", "%b3", x)
  gsub("\\xb4", "%b4", x)
  gsub("\\xb5", "%b5", x)
  gsub("\\xb6", "%b6", x)
  gsub("\\xb7", "%b7", x)
  gsub("\\xb8", "%b8", x)
  gsub("\\xb9", "%b9", x)
  gsub("\\xba", "%ba", x)
  gsub("\\xbb", "%bb", x)
  gsub("\\xbc", "%bc", x)
  gsub("\\xbd", "%bd", x)
  gsub("\\xbe", "%be", x)
  gsub("\\xbf", "%bf", x)

  gsub("\\xc0", "%c0", x)
  gsub("\\xc1", "%c1", x)
  gsub("\\xc2", "%c2", x)
  gsub("\\xc3", "%c3", x)
  gsub("\\xc4", "%c4", x)
  gsub("\\xc5", "%c5", x)
  gsub("\\xc6", "%c6", x)
  gsub("\\xc7", "%c7", x)
  gsub("\\xc8", "%c8", x)
  gsub("\\xc9", "%c9", x)
  gsub("\\xca", "%ca", x)
  gsub("\\xcb", "%cb", x)
  gsub("\\xcc", "%cc", x)
  gsub("\\xcd", "%cd", x)
  gsub("\\xce", "%ce", x)
  gsub("\\xcf", "%cf", x)

  gsub("\\xd0", "%d0", x)
  gsub("\\xd1", "%d1", x)
  gsub("\\xd2", "%d2", x)
  gsub("\\xd3", "%d3", x)
  gsub("\\xd4", "%d4", x)
  gsub("\\xd5", "%d5", x)
  gsub("\\xd6", "%d6", x)
  gsub("\\xd7", "%d7", x)
  gsub("\\xd8", "%d8", x)
  gsub("\\xd9", "%d9", x)
  gsub("\\xda", "%da", x)
  gsub("\\xdb", "%db", x)
  gsub("\\xdc", "%dc", x)
  gsub("\\xdd", "%dd", x)
  gsub("\\xde", "%de", x)
  gsub("\\xdf", "%df", x)

  gsub("\\xe0", "%e0", x)
  gsub("\\xe1", "%e1", x)
  gsub("\\xe2", "%e2", x)
  gsub("\\xe3", "%e3", x)
  gsub("\\xe4", "%e4", x)
  gsub("\\xe5", "%e5", x)
  gsub("\\xe6", "%e6", x)
  gsub("\\xe7", "%e7", x)
  gsub("\\xe8", "%e8", x)
  gsub("\\xe9", "%e9", x)
  gsub("\\xea", "%ea", x)
  gsub("\\xeb", "%eb", x)
  gsub("\\xec", "%ec", x)
  gsub("\\xed", "%ed", x)
  gsub("\\xee", "%ee", x)
  gsub("\\xef", "%ef", x)

  gsub("\\xf0", "%f0", x)
  gsub("\\xf1", "%f1", x)
  gsub("\\xf2", "%f2", x)
  gsub("\\xf3", "%f3", x)
  gsub("\\xf4", "%f4", x)
  gsub("\\xf5", "%f5", x)
  gsub("\\xf6", "%f6", x)
  gsub("\\xf7", "%f7", x)
  gsub("\\xf8", "%f8", x)
  gsub("\\xf9", "%f9", x)
  gsub("\\xfa", "%fa", x)
  gsub("\\xfb", "%fb", x)
  gsub("\\xfc", "%fc", x)
  gsub("\\xfd", "%fd", x)
  gsub("\\xfe", "%fe", x)
  gsub("\\xff", "%ff", x)

  return x
}
BEGIN {
	host=ENVIRON["host"] ":" ENVIRON["port"]
}
/^[a-zA-Z0-9]/ {
	size=$2
	urn=$1
	if (!match(urn, "^urn:")) {
		urn="urn:sha1:" urn
	}
	url="http://" host "/uri-res/N2R?" urn
	name=$0
	gsub("^.*[/]", "", name)
	name=urlencode(name)
	printf("magnet:?dn=%s&xs=%s&xl=%s\n", name, url, size) 
}' "${sha1_cache}"
