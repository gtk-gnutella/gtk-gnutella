/*
 * $Id$
 *
 * Copyright (c) 2002-2004, Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * GGEP type-specific routines.
 *
 * @author Raphael Manfredi
 * @date 2002-2004
 */

#include "common.h"

RCSID("$Id$")

#include "ggep.h"
#include "ggep_type.h"
#include "hosts.h"				/* For struct gnutella_host */

#include "lib/endian.h"
#include "lib/gnet_host.h"
#include "lib/misc.h"
#include "lib/unsigned.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "if/core/search.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Extract the SHA1 hash of the "H" extension into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * the SHA1 in 'sha1'.
 */
ggept_status_t
ggept_h_sha1_extract(extvec_t *exv, struct sha1 *sha1)
{
	const char *payload;
	size_t tlen;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_H);

	/*
	 * Try decoding as a SHA1 hash, which is <type> <sha1_digest>
	 * for a total of 21 bytes.  We also allow BITRPINT hashes, since the
	 * first 20 bytes of the binary bitprint is actually the SHA1.
	 */

	tlen = ext_paylen(exv);
	if (tlen <= 1)
		return GGEP_INVALID;			/* Can't be a valid "H" payload */

	payload = ext_payload(exv);

	if (payload[0] == GGEP_H_SHA1) {
		if (tlen != (SHA1_RAW_SIZE + 1))
			return GGEP_INVALID;			/* Size is not right */
	} else if (payload[0] == GGEP_H_BITPRINT) {
		if (tlen != (BITPRINT_RAW_SIZE + 1))
			return GGEP_INVALID;			/* Size is not right */
	} else
		return GGEP_NOT_FOUND;

	memcpy(sha1->data, &payload[1], SHA1_RAW_SIZE);

	return GGEP_OK;
}

/**
 * Extract the TTH hash of the "H" extension into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * the TTH in 'tth'.
 */
ggept_status_t
ggept_h_tth_extract(extvec_t *exv, struct tth *tth)
{
	const char *payload;
	size_t tlen;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_H);

	tlen = ext_paylen(exv);
	if (tlen <= 1)
		return GGEP_INVALID;			/* Can't be a valid "H" payload */

	payload = ext_payload(exv);
	if (payload[0] != GGEP_H_BITPRINT)
		return GGEP_NOT_FOUND;
	
	if (tlen != (BITPRINT_RAW_SIZE + 1))
		return GGEP_INVALID;			/* Size is not right */

	memcpy(tth->data, &payload[1 + SHA1_RAW_SIZE], TTH_RAW_SIZE);

	return GGEP_OK;
}
/**
 * Extract payload information from "GTKGV1" into `info'.
 */
ggept_status_t
ggept_gtkgv1_extract(extvec_t *exv, struct ggep_gtkgv1 *info)
{
	const char *payload;
	const char *p;
	int tlen;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_GTKGV1);

	tlen = ext_paylen(exv);

	if (tlen != 12)
		return GGEP_INVALID;

	payload = p = ext_payload(exv);

	info->major = p[0];
	info->minor = p[1];
	info->patch = p[2];
	info->revchar = p[3];
	info->release = peek_be32(&p[4]);
	info->build = peek_be32(&p[8]);

	return GGEP_OK;
}

static ggept_status_t
ggept_ip_vec_extract(extvec_t *exv, gnet_host_vec_t **hvec)
{
	int len;

	g_assert(exv);
	g_assert(hvec);
	g_assert(EXT_GGEP == exv->ext_type);

	len = ext_paylen(exv);

	if (len <= 0)
		return GGEP_INVALID;

	if (len % 6 != 0)
		return GGEP_INVALID;

	if (hvec) {
		gnet_host_vec_t *vec;
		const char *p;
		guint n, i;

		vec = gnet_host_vec_alloc();
		n = len / 6;
		n = MIN(n, 255);	/* n_ipv4 is guint8 */
		vec->n_ipv4 = n;
		vec->hvec_v4 = walloc(n * sizeof vec->hvec_v4[0]);

		p = ext_payload(exv);
		for (i = 0; i < n; i++) {
			/* IPv4 address (BE) + Port (LE) */
			memcpy(&vec->hvec_v4[i].data, p, 6);
			p += 6;
		}
		*hvec = vec;
	}

	return GGEP_OK;
}

/**
 * Extract vector of IP:port alternate locations.
 *
 * @param `exv'		no brief description.
 * @param `hvec'	pointer is filled with a dynamically allocated vector.
 *
 * Unless GGEP_OK is returned, no memory allocation takes place.
 */
ggept_status_t
ggept_alt_extract(extvec_t *exv, gnet_host_vec_t **hvec) 
{
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_ALT);

	return ggept_ip_vec_extract(exv, hvec);
}

/**
 * Extract vector of IP:port push proxy locations.
 *
 * The `hvec' pointer is filled with a dynamically allocated vector.
 *
 * Unless GGEP_OK is returned, no memory allocation takes place.
 */
ggept_status_t
ggept_push_extract(extvec_t *exv, gnet_host_vec_t **hvec)
{
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_PUSH);

	return ggept_ip_vec_extract(exv, hvec);
}

/**
 * Extract an UTF-8 encoded string into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * extracted something in the supplied buffer.
 */
ggept_status_t
ggept_utf8_string_extract(extvec_t *exv, char *buf, size_t len)
{
	int tlen;

	g_assert(size_is_non_negative(len));
	g_assert(exv->ext_type == EXT_GGEP);

	/*
	 * The payload should not contain a NUL.
	 * We only copy up to the first NUL.
	 * The empty string is accepted.
	 */

	tlen = ext_paylen(exv);
	if (tlen < 0 || UNSIGNED(tlen) >= len)
		return GGEP_INVALID;

	clamp_strncpy(buf, len, ext_payload(exv), tlen);

	if (!utf8_is_valid_string(buf))
		return GGEP_INVALID;

	return GGEP_OK;
}

/**
 * Extract hostname of the "HNAME" extension into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * extracted something in the supplied buffer.
 */
ggept_status_t
ggept_hname_extract(extvec_t *exv, char *buf, int len)
{
	g_assert(len >= 0);
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_HNAME);

	if (GGEP_OK != ggept_utf8_string_extract(exv, buf, len))
		return GGEP_INVALID;

	/*
	 * Make sure the full string qualifies as hostname and is not an
	 * IP address.
	 */
	{
		const char *endptr;
		host_addr_t addr;

		if (
			!string_to_host_or_addr(buf, &endptr, &addr) ||
			'\0' != *endptr ||
			is_host_addr(addr)
		) {
			return GGEP_INVALID;
		}
	}

	return GGEP_OK;
}

/**
 * Encodes a variable-length integer. This encoding is equivalent to
 * little-endian encoding whereas trailing zeros are discarded.
 *
 * @param v		The value to encode.
 * @param data  Must point to a sufficiently large buffer. At maximum
 *				8 bytes are required.
 *
 * @return the length in bytes of the encoded variable-length integer.
 */
static inline int
ggep_vlint_encode(guint64 v, char *data)
{
	char *p;

	for (p = data; v != 0; v >>= 8)	{
		*p++ = v & 0xff;
	}

	return p - data;
}

/**
 * Decodes a variable-length integer. This encoding is equivalent to
 * little-endian encoding whereas trailing zeros are discarded.
 *
 * @param data The payload to decode.
 * @param len The length of data in bytes.
 *
 * @return The decoded value.
 */
static inline guint64
ggep_vlint_decode(const char *data, size_t len)
{
	guint64 v;
	guint i;

	v = 0;
	if (len <= 8) {
		for (i = 0; i < len; i++) {
			v |= (((guint64) data[i]) & 0xff) << (i * 8);
		}
	}
	return v;
}

/**
 * Extract filesize length into `filesize' from extension encoded in variable-
 * length little endian with leading zeroes stripped.
 *
 * This is the format used by the payload of GGEP "LF" for instance.
 */
ggept_status_t
ggept_filesize_extract(extvec_t *exv, guint64 *filesize)
{
	guint64 fs;
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);

	len = ext_paylen(exv);
	if (len < 1 || len > 8) {
		return GGEP_INVALID;
	}
	fs = ggep_vlint_decode(ext_payload(exv), len);
	if (0 == fs) {
		return GGEP_INVALID;
	}
	if (filesize) {
		*filesize = fs;
	}
	return GGEP_OK;
}

/**
 * Extract IPv6 address into `addr' from GGEP "GTKG.IPV6" extension.
 * A zero length indicates IPv6 support, a length of 16 or more
 * indicates that the first 16 bytes are a IPv6 address.
 */
ggept_status_t
ggept_gtkg_ipv6_extract(extvec_t *exv, host_addr_t *addr)
{
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_GTKG_IPV6);

	len = ext_paylen(exv);
	if (0 != len && 16 < len)
		return GGEP_INVALID;

	if (addr) {
		if (0 == len) {
			*addr = zero_host_addr;
		} else {
			g_assert(len >= 16);
			*addr = host_addr_peek_ipv6(ext_payload(exv));
		}
	}

	return GGEP_OK;
}


/**
 * Encode `filesize' in variable-length little endian, with leading zeroes
 * stripped, into `data'.
 *
 * This is used in extensions such as GGEP "LF" which carry the file length.
 *
 * @param filesize	The filesize to encode.
 * @param data		A buffer of at least 8 bytes.
 *
 * @return the amount of bytes written.
 */
guint
ggept_filesize_encode(guint64 filesize, char *data)
{
	return ggep_vlint_encode(filesize, data);
}

/**
 * Extract daily uptime into `uptime', from the GGEP "DU" extensions.
 */
ggept_status_t
ggept_du_extract(extvec_t *exv, guint32 *uptime)
{
	guint32 up;
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_DU);

	len = ext_paylen(exv);
	if (len > 4) {
		return GGEP_INVALID;
	}
	up = ggep_vlint_decode(ext_payload(exv), len);
	if (uptime) {
		*uptime = up;
	}
	return GGEP_OK;
}

/**
 * Encode `uptime' for the GGEP "DU" extension into `data'.
 *
 * @param uptime The uptime (in seconds) to encode.
 * @param data A buffer of at least 4 bytes.
 * @return the amount of chars written.
 */
guint
ggept_du_encode(guint32 uptime, char *data)
{
	return ggep_vlint_encode(uptime, data);
}

ggept_status_t
ggept_ct_extract(extvec_t *exv, time_t *stamp_ptr)
{
	guint64 v;
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_CT);

	len = ext_paylen(exv);
	if (len > 8) {
		return GGEP_INVALID;
	}
	v = ggep_vlint_decode(ext_payload(exv), len);
	if (stamp_ptr) {
		*stamp_ptr = MIN(v, TIME_T_MAX);
	}
	return GGEP_OK;
}

/**
 * Encode `timestamp' for the GGEP "CT" extension into `data'.
 *
 * @param timestamp The timestamp (seconds since epoch) to encode.
 * @param data A buffer of at least 8 bytes.
 * @return the amount of chars written.
 */
guint
ggept_ct_encode(time_t timestamp, char *data)
{
	return ggep_vlint_encode(timestamp, data);
}

/* vi: set ts=4 sw=4 cindent: */
