/*
 * $Id$
 *
 * Copyright (c) 2002-2004, Raphael Manfredi
 *
 * GGEP type-specific routines.
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

#include "common.h"

RCSID("$Id$");

#include "ggep.h"
#include "ggep_type.h"
#include "hosts.h"				/* For struct gnutella_host */
#include "lib/endian.h"
#include "lib/walloc.h"

#include "if/core/hosts.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Extract the SHA1 hash of the "H" extension into the supplied buffer.
 *
 * Returns extraction status: only when GGEP_OK is returned will we have
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

#define TIGER_RAW_SIZE	24		/* XXX temporary, until we implement tiger */

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
	READ_GUINT32_BE(p, info->start);
	p += 4;

	g_assert(p - payload == 12);

	return GGEP_OK;
}

/**
 * Extract vector of IP:port alternate locations.
 *
 * The `hvec' pointer is filled with a dynamically allocated vector, and
 * the `hvcnt' is filled with the size of the allocated vector (number of
 * items).
 *
 * Unless GGEP_OK is returned, no memory allocation takes place.
 */
ggept_status_t
ggept_alt_extract(extvec_t *exv, struct gnutella_host **hvec, gint *hvcnt)
{
	const gchar *p;
	gint tlen;
	gint cnt;
	struct gnutella_host *vec;
	struct gnutella_host *h;
	gint i;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_ALT);

	tlen = ext_paylen(exv);

	if (tlen <= 0)
		return GGEP_INVALID;

	if (tlen % 6 != 0)
		return GGEP_INVALID;

	p = ext_payload(exv);

	cnt = tlen / 6;
	vec = walloc(cnt * sizeof(struct gnutella_host));

	for (i = 0, h = vec; i < cnt; i++, h++) {
		READ_GUINT32_BE(p, h->ip);
		p += 4;
		READ_GUINT16_LE(p, h->port);
		p += 2;
	}

	*hvec = vec;
	*hvcnt = cnt;

	return GGEP_OK;
}

/**
 * Extract vector of IP:port push proxy locations.
 *
 * The `hvec' pointer is filled with a dynamically allocated vector, and
 * the `hvcnt' is filled with the size of the allocated vector (number of
 * items).
 *
 * Unless GGEP_OK is returned, no memory allocation takes place.
 */
ggept_status_t
ggept_push_extract(extvec_t *exv, struct gnutella_host **hvec, gint *hvcnt)
{
	const gchar *p;
	gint tlen;
	gint cnt;
	struct gnutella_host *vec;
	struct gnutella_host *h;
	gint i;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_PUSH);

	tlen = ext_paylen(exv);

	if (tlen <= 0)
		return GGEP_INVALID;

	if (tlen % 6 != 0)
		return GGEP_INVALID;

	p = ext_payload(exv);

	cnt = tlen / 6;
	vec = walloc(cnt * sizeof(struct gnutella_host));

	for (i = 0, h = vec; i < cnt; i++, h++) {
		READ_GUINT32_BE(p, h->ip);
		p += 4;
		READ_GUINT16_LE(p, h->port);
		p += 2;
	}

	*hvec = vec;
	*hvcnt = cnt;

	return GGEP_OK;
}

/**
 * Extract hostname of the "HNAME" extension into the supplied buffer.
 * Returns extraction status: only when GGEP_OK is returned will we have
 * extracted something in the supplied buffer.
 */
ggept_status_t
ggept_hname_extract(extvec_t *exv, gchar *buf, gint len)
{
	gint tlen;
	gint slen;
	const gchar *payload;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_HNAME);

	/*
	 * Leave out one character at the end to be able to store the trailing
	 * NUL, which is not included in the extension.
	 */

	tlen = ext_paylen(exv);

	if (tlen <= 0)
		return GGEP_INVALID;

	payload = ext_payload(exv);
	slen = MIN(tlen, len - 1);

	memcpy(buf, payload, slen);

	buf[slen] = '\0';

	return GGEP_OK;
}

/**
 * Extract filesize length into `filesize' from GGEP "LF" extension.
 */
ggept_status_t
ggept_lf_extract(extvec_t *exv, guint64 *filesize)
{
	guint64 fs, b;
	gint i, j, tlen;
	const guint8 *payload;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_LF);

	tlen = ext_paylen(exv);

	if (tlen < 1 || tlen > 8)
		return GGEP_INVALID;

	payload = ext_payload(exv);

	fs = j = i = 0;
	do {
		b = payload[i];
		fs |= b << j;
		j += 8;
	} while (++i < tlen);

	if (0 == b)
		return GGEP_INVALID;

	if (filesize)
		*filesize = fs;

	return GGEP_OK;
}

/**
 * Encode `filesize' for the GGEP "LF" extension into `data'.
 * @return the amount of chars written.
 */
gint
ggept_lf_encode(guint64 filesize, guint8 *data)
{
	guint8 *p = data;

	if (0 == filesize)
		return 0;

	do {
		*p++ = filesize;
	} while (0 != (filesize >>= 8));

	return p - data;
}

/**
 * Extract daily uptime into `uptime', from the GGEP "DU" extensions.
 */
ggept_status_t
ggept_du_extract(extvec_t *exv, guint32 *uptime)
{
	guint32 up, b;
	gint i, j, tlen;
	const gchar *payload;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_DU);

	tlen = ext_paylen(exv);

	if (tlen < 1 || tlen > 4)
		return GGEP_INVALID;

	payload = ext_payload(exv);

	up = j = i = 0;
	do {
		b = payload[i];
		up |= b << j;
		j += 8;
	} while (++i < tlen);

	if (uptime)
		*uptime = up;

	return GGEP_OK;
}

/**
 * Encode `uptime' for the GGEP "DU" extension into `data'.
 * @return the amount of chars written.
 */
gint
ggept_du_encode(guint32 uptime, guint8 *data)
{
	guint8 *p = data;

	if (0 == uptime)
		return 0;

	do {
		*p++ = uptime;
	} while (0 != (uptime >>= 8));

	return p - data;
}

/* vi: set ts=4 sw=4 cindent: */
