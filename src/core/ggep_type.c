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
#include "lib/misc.h"
#include "lib/walloc.h"

#include "if/core/hosts.h"
#include "if/core/search.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Extract the SHA1 hash of the "H" extension into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * the SHA1 in buf.
 */
ggept_status_t
ggept_h_sha1_extract(extvec_t *exv, gchar *buf, gint len)
{
	const gchar *payload;
	gint tlen;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_H);
	g_assert(len >= SHA1_RAW_SIZE);

	/*
	 * Try decoding as a SHA1 hash, which is <type> <sha1_digest>
	 * for a total of 21 bytes.  We also allow BITRPINT hashes, since the
	 * first 20 bytes of the binary bitprint is actually the SHA1.
	 */

	tlen = ext_paylen(exv);

#define TIGER_RAW_SIZE	24		/**< XXX temporary, until we implement tiger */

	if (tlen == -1)
		return GGEP_NOT_FOUND;			/* Don't know what this is */

	if (tlen <= 1)
		return GGEP_INVALID;			/* Can't be a valid "H" payload */

	payload = ext_payload(exv);

	if (payload[0] == GGEP_H_SHA1) {
		if (tlen != (SHA1_RAW_SIZE + 1))
			return GGEP_INVALID;			/* Size is not right */
	} else if (payload[0] == GGEP_H_BITPRINT) {
		if (tlen != (SHA1_RAW_SIZE + TIGER_RAW_SIZE + 1))
			return GGEP_INVALID;			/* Size is not right */
	} else
		return GGEP_NOT_FOUND;

	memcpy(buf, &payload[1], SHA1_RAW_SIZE);

	return GGEP_OK;
}

/**
 * Extract payload information from "GTKGV1" into `info'.
 */
ggept_status_t
ggept_gtkgv1_extract(extvec_t *exv, struct ggep_gtkgv1 *info)
{
	const gchar *payload;
	const gchar *p;
	gint tlen;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_GTKGV1);

	tlen = ext_paylen(exv);

	if (tlen != 12)
		return GGEP_INVALID;

	payload = p = ext_payload(exv);

	info->major = *p++;
	info->minor = *p++;
	info->patch = *p++;
	info->revchar = *p++;

	READ_GUINT32_BE(p, info->release);
	p += 4;
	READ_GUINT32_BE(p, info->build);
	p += 4;

	g_assert(p - payload == 12);

	return GGEP_OK;
}

static ggept_status_t
ggept_ip_vec_extract(extvec_t *exv, gnet_host_vec_t **hvec)
{
	gint len;

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
		const gchar *p;
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
 * Extract hostname of the "HNAME" extension into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * extracted something in the supplied buffer.
 */
ggept_status_t
ggept_hname_extract(extvec_t *exv, gchar *buf, gint len)
{
	gint tlen;
	gint slen;
	const gchar *payload;

	g_assert(len >= 0);
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_HNAME);

	/*
	 * Leave out one character at the end to be able to store the trailing
	 * NUL, which is not included in the extension.
	 */

	tlen = ext_paylen(exv);
	if (tlen <= 0 || tlen >= len)
		return GGEP_INVALID;

	payload = ext_payload(exv);
	slen = MIN(tlen, len - 1);

	memcpy(buf, payload, slen);
	buf[slen] = '\0';

	/*
	 * Make sure the full string qualifies as hostname and is not an
	 * IP address.
	 */
	{
		const gchar *endptr;
		host_addr_t addr;

		if (
			!string_to_host_or_addr(buf, &endptr, &addr) ||
			&buf[slen] != endptr ||
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
 * @param v the value to encode.
 * @param data must point to a sufficiently large buffer.
 *
 * @return the length in bytes of the encoded variable-length integer.
 */
static inline gint
ggep_vlint_encode(guint64 v, gchar *data)
{
	gchar *p;

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
ggep_vlint_decode(const gchar *data, size_t len)
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
 * Extract filesize length into `filesize' from GGEP "LF" extension.
 */
ggept_status_t
ggept_lf_extract(extvec_t *exv, guint64 *filesize)
{
	guint64 fs;
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_LF);

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
			*addr = host_addr_peek_ipv6(
						cast_to_gconstpointer(ext_payload(exv)));
		}
	}

	return GGEP_OK;
}


/**
 * Encode `filesize' for the GGEP "LF" extension into `data'.
 *
 * @return the amount of chars written.
 */
gint
ggept_lf_encode(guint64 filesize, gchar *data)
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
	if (len < 0 || len > 4) {
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
 * @return the amount of chars written.
 */
gint
ggept_du_encode(guint32 uptime, gchar *data)
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
	if (len < 0 || len > 8) {
		return GGEP_INVALID;
	}
	v = ggep_vlint_decode(ext_payload(exv), len);
	if (stamp_ptr) {
		*stamp_ptr = MIN(v, TIME_T_MAX);
	}
	return GGEP_OK;
}

/**
 * @return the amount of chars written.
 */
gint
ggept_ct_encode(time_t stamp, gchar *data)
{
	return ggep_vlint_encode(stamp, data);
}

/* vi: set ts=4 sw=4 cindent: */
