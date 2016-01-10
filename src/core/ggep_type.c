/*
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

#include "ggep.h"
#include "ggep_type.h"
#include "hosts.h"				/* For struct gnutella_host */
#include "ipp_cache.h"			/* For tls_cache_lookup() */
#include "qhit.h"				/* For QHIT_F_* flags */
#include "version.h"			/* For version_is_dirty(), etc.. */

#include "lib/bstr.h"
#include "lib/endian.h"
#include "lib/getdate.h"
#include "lib/gnet_host.h"
#include "lib/log.h"
#include "lib/misc.h"
#include "lib/product.h"
#include "lib/sequence.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/utf8.h"
#include "lib/vector.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"
#include "if/core/search.h"

#include "lib/override.h"		/* Must be the last header included */

static time_t release_date;

/**
 * Initialization of the "release date" variable.
 */
static void
ggept_release_date_init(void)
{
	release_date = date2time(product_date(), tm_time());
}

/**
 * Extract the SHA1 hash of the "H" extension into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * the SHA1 in 'sha1'.
 */
ggept_status_t
ggept_h_sha1_extract(const extvec_t *exv, struct sha1 *sha1)
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
ggept_h_tth_extract(const extvec_t *exv, struct tth *tth)
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
 * The known OS names we encode into the GTKGV extension.
 */
static const char *gtkgv_osname[] = {
	"Unknown OS",				/* 0 */
	"UNIX",						/* 1 */
	"BSD",						/* 2 */
	"Linux",					/* 3 */
	"FreeBSD",					/* 4 */
	"NetBSD",					/* 5 */
	"Windows",					/* 6 */
	"Darwin",					/* 7 */
};

/**
 * @return the OS name encoded into a GTKGV extension.
 */
static const char *
ggept_gtkgv_osname(uint8 value)
{
	return value >= G_N_ELEMENTS(gtkgv_osname) ?
		gtkgv_osname[0] : gtkgv_osname[value];
}

/**
 * Given a system name, look how it should be encoded in GTKGV.
 */
static uint8
ggept_gtkgv_osname_encode(const char *sysname)
{
	uint8 result = 0;
	size_t i;

	/*
	 * First some defaults in case we don't get an exact match.
	 */

	if (is_running_on_mingw())
		result = 6;
	else if (strstr(sysname, "BSD"))
		result = 2;
	else
		result = 1;

	/*
	 * Now attempt a case-insensitive match to see whether we have
	 * something more specific to use than the defaults.
	 */

	for (i = 3; i < G_N_ELEMENTS(gtkgv_osname); i++) {
		if (0 == strcasecmp(sysname, gtkgv_osname[i])) {
			result = i;
			break;
		}
	}

	if (GNET_PROPERTY(ggep_debug)) {
		g_debug("GGEP encoded OS name \"%s\" in GTKGV will be %u",
			sysname, result);
	}

	return result;
}

/**
 * @return the value that should be advertised as the OS name in "GTKGV".
 */
static uint8
ggept_gtkgv_osname_value(void)
{
	static uint8 result = -1;

	/*
	 * Computation only happens once.
	 */

	if (result >= G_N_ELEMENTS(gtkgv_osname)) {
#ifdef HAS_UNAME
		{
			struct utsname un;

			if (-1 != uname(&un)) {
				result = ggept_gtkgv_osname_encode(un.sysname);
			} else {
				s_carp("uname() failed: %m");
			}
		}
#else
		result = 0;
#endif /* HAS_UNAME */
	}

	return result;
}

/**
 * Extract payload information from "GTKGV" into `info'.
 *
 * @param buf	start of payload
 * @param len	length of payload
 * @param info	where information is decompiled
 *
 * @return GGEP_OK if OK
 */
ggept_status_t
ggept_gtkgv_extract_data(const void *buf, size_t len, struct ggep_gtkgv *info)
{
	const char *p = buf;
	ggept_status_t status = GGEP_OK;

	g_assert(buf != NULL);
	g_assert(size_is_non_negative(len));
	g_assert(info != NULL);

	/*
	 * The original payload length was 13 bytes.
	 *
	 * In order to allow backward-compatible extension of the payload, don't
	 * check for a size equal to 13 bytes but for a size of at least 13.
	 *
	 * Further extensions, if any, will simply append new fields to the payload
	 * which will be ignored (not deserialized) by older versions.  Since the
	 * version number is serialized, it will be possible to derive default
	 * values for older versions of the payload.
	 */

	if (len < 13)
		return GGEP_INVALID;

	info->version = p[0];
	info->major = p[1];
	info->minor = p[2];
	info->patch = p[3];
	info->revchar = p[4];
	info->release = peek_be32(&p[5]);
	info->build = peek_be32(&p[9]);

	info->dirty = FALSE;
	info->commit_len = 0;
	ZERO(&info->commit);
	info->osname = NULL;

	if (info->version >= 1) {
		bstr_t *bs;
		uint8 flags;

		bs = bstr_open(p, len, GNET_PROPERTY(ggep_debug) ? BSTR_F_ERROR : 0);
		bstr_skip(bs, 13);

		if (bstr_read_u8(bs, &flags)) {
			uint8 aflags = flags;

			/*
			 * Swallow extra flags, if present (for now we expect only 1 byte).
			 */

			while ((aflags & GTKGV_F_CONT) && bstr_read_u8(bs, &aflags))
				/* empty */;


			info->dirty = booleanize(aflags & GTKGV_F_DIRTY);

			/*
			 * Process git commit SHA1, if present.
			 */

			if (aflags & GTKGV_F_GIT) {
				if (
					bstr_read_u8(bs, &info->commit_len) &&
					info->commit_len != 0
				) {
					if (info->commit_len <= 2 * SHA1_RAW_SIZE) {
						uint8 bytes = (info->commit_len + 1) / 2;
						if (!bstr_read(bs, &info->commit, bytes)) {
							status = GGEP_INVALID;
						}
					} else {
						status = GGEP_INVALID;
					}
				}
			}

			/*
			 * Process OS information is present and we got no error so far.
			 */

			if ((aflags & GTKGV_F_OS) && GGEP_OK == status) {
				uint8 value;

				if (bstr_read_u8(bs, &value)) {
					info->osname = ggept_gtkgv_osname(value);
				}
			}
		}

		bstr_free(&bs);
	}

	return status;
}

/**
 * Extract payload information from "GTKGV" into `info'.
 */
ggept_status_t
ggept_gtkgv_extract(const extvec_t *exv, struct ggep_gtkgv *info)
{
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_GTKGV);

	return ggept_gtkgv_extract_data(ext_payload(exv), ext_paylen(exv), info);
}

/**
 * Build the "GTKGV" payload into supplied buffer (which must be GTKGV_MAX_LEN
 * bytes long).
 *
 * @return the length of the GTKGV extension built.
 */
size_t
ggept_gtkgv_build(void *buf, size_t len)
{
	uint8 major = product_major();
	uint8 minor = product_minor();
	uint8 revchar = product_revchar();
	uint8 patch = product_patchlevel();
	uint32 release;
	uint32 date;
	uint32 build;
	uint8 version = 1;		/* This is GTKGV version 1 */
	uint8 osname;
	uint8 flags;
	uint8 commit_len;
	size_t commit_bytes;
	const sha1_t *commit;
	str_t s;

	/*
	 * We can conveniently use a "string" to write binary data, because
	 * GTKGV_MAX_LEN accounts for the trailing NUL byte that the string
	 * package invariably accounts for.
	 */

	str_new_buffer(&s, buf, 0, len);

	flags = GTKGV_F_GIT | GTKGV_F_OS;
	if (version_is_dirty())
		flags |= GTKGV_F_DIRTY;

	if G_UNLIKELY(0 == release_date)
		ggept_release_date_init();

	date = release_date;
	poke_be32(&release, date);
	poke_be32(&build, product_build());

	commit = version_get_commit(&commit_len);
	commit_bytes = (1 + commit_len) / 2;
	osname = ggept_gtkgv_osname_value();

	str_putc(&s, version);
	str_putc(&s, major);
	str_putc(&s, minor);
	str_putc(&s, patch);
	str_putc(&s, revchar);
	str_cat_len(&s, (char *) &release, 4);
	str_cat_len(&s, (char *) &build, 4);
	str_putc(&s, flags);
	str_putc(&s, commit_len);
	str_cat_len(&s, (char *) commit, commit_bytes);
	str_putc(&s, osname);

	return str_len(&s);
}

/**
 * Extract payload information from "GTKGV1" into `info'.
 */
ggept_status_t
ggept_gtkgv1_extract(const extvec_t *exv, struct ggep_gtkgv1 *info)
{
	const char *p;
	int tlen;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_GTKGV1);

	tlen = ext_paylen(exv);

	if (tlen < 12)
		return GGEP_INVALID;

	p = ext_payload(exv);

	info->major = p[0];
	info->minor = p[1];
	info->patch = p[2];
	info->revchar = p[3];
	info->release = peek_be32(&p[4]);
	info->build = peek_be32(&p[8]);

	return GGEP_OK;
}

/**
 * From a sequence of IP:port addresses, fill a set of GGEP extensions:
 *
 *		N and N_TLS
 *
 * for the given network type.
 *
 * @param gs		the GGEP stream to which extensions are written
 * @param hseq		sequence of IP:port (IPv4 and IPv6 mixed)
 * @param net		network address type
 * @param name		name of GGEP extension for addresses
 * @param name_tls	name of GGEP extension for TLS
 * @param evec		optional exclusion address vector
 * @param ecnt		length of evec[]
 * @param count		input: max amount of items to generate, output: items sent
 * @param cobs		whether COBS encoding is required
 *
 * @return TRUE on success, FALSE on write errors.
 */
static bool
ggept_ip_seq_append_net(ggep_stream_t *gs,
	const sequence_t *hseq, enum net_type net,
	const char *name, const char *name_tls,
	const gnet_host_t *evec, size_t ecnt, size_t *count, bool cobs)
{
	uchar *tls_bytes = NULL;
	unsigned tls_length;
	size_t tls_size = 0, tls_index = 0;
	bool status = FALSE;
	unsigned flags = 0;
	size_t hcnt;
	const char *current_extension;
	sequence_iter_t *iter = NULL;
	size_t max_items = *count;

	g_assert(gs != NULL);
	g_assert(name != NULL);
	g_assert(hseq != NULL);

	hcnt = sequence_count(hseq);

	if (0 == hcnt) {
		status = TRUE;
		goto done;
	}

	tls_size = (hcnt + 7) / 8;
	tls_bytes = name_tls != NULL ? walloc0(tls_size) : NULL;
	tls_index = tls_length = 0;

	/*
	 * We only attempt to deflate IPv6 vectors, since IPv4 does not bring
	 * enough redundancy to be worth it: 180 bytes of data for 30 IPv4
	 * addresses typically compress to 175 bytes.  Hardly interesting.
	 */

	flags |= (NET_TYPE_IPV6 == net) ? GGEP_W_DEFLATE : 0;
	flags |= cobs ? GGEP_W_COBS : 0;

	/*
	 * We use GGEP_W_STRIP to make sure the extension is removed if empty.
	 */

	current_extension = name;

	if (!ggep_stream_begin(gs, name, GGEP_W_STRIP | flags))
		goto done;

	iter = sequence_forward_iterator(hseq);

	while (sequence_iter_has_next(iter) && tls_index < max_items) {
		host_addr_t addr;
		uint16 port;
		char buf[18];
		size_t len;
		const gnet_host_t *h = sequence_iter_next(iter);

		if (net != gnet_host_get_net(h))
			continue;

		/*
		 * See whether we need to skip that host.
		 */

		if (evec != NULL) {
			size_t i;

			for (i = 0; i < ecnt; i++) {
				if (gnet_host_equiv(h, &evec[i]))
					goto next;
			}
		}

		addr = gnet_host_get_addr(h);
		port = gnet_host_get_port(h);

		host_ip_port_poke(buf, addr, port, &len);
		if (!ggep_stream_write(gs, buf, len))
			goto done;

		/*
		 * Record in bitmask whether host is known to support TLS.
		 */

		if (name_tls != NULL && tls_cache_lookup(addr, port)) {
			tls_bytes[tls_index >> 3] |= 0x80U >> (tls_index & 7);
			tls_length = (tls_index >> 3) + 1;
		}
		tls_index++;
	next:
		continue;
	}

	if (!ggep_stream_end(gs))
		goto done;

	if (tls_length > 0) {
		unsigned gflags = cobs ? GGEP_W_COBS : 0;
		g_assert(name_tls != NULL);
		current_extension = name_tls;
		if (!ggep_stream_pack(gs, name_tls, tls_bytes, tls_length, gflags))
			goto done;
	}

	status = TRUE;

done:
	if (!status) {
		g_carp("unable to add GGEP \"%s\": %s",
			current_extension, ggep_errstr());
	}

	*count = tls_index;

	sequence_iterator_release(&iter);
	WFREE_NULL(tls_bytes, tls_size);
	return status;
}

/**
 * From a sequence of IP:port addresses fill two sets of GGEP extensions:
 *
 *    NAME and NAME_TLS for IPv4 addresses
 *    NAME6 and NAME6_TLS for IPv6 addresses
 *
 * @param gs		the GGEP stream to which extensions are written
 * @param hseq		sequence of IP:port (IPv4 and IPv6 mixed)
 * @param name		name of GGEP extension for IPv4 addresses
 * @param name_tls	name of GGEP extension for TLS vector of IPv4 addresses
 * @param name6		name of GGEP extension for IPv6 addresses
 * @param name6_tls	name of GGEP extension for TLS vector of IPv6 addresses
 * @param evec		optional exclusion address vector
 * @param ecnt		length of evec[]
 * @param max_items	maximum amount of items to include, (size_t) -1 means all
 * @param cobs		whether COBS encoding is required
 *
 * @return GGEP_OK on success, GGEP_BAD_SIZE on write errors.
 */
static ggept_status_t
ggept_ip_seq_append(ggep_stream_t *gs,
	const sequence_t *hseq,
	const char *name, const char *name_tls,
	const char *name6, const char *name6_tls,
	const gnet_host_t *evec, size_t ecnt, size_t max_items, bool cobs)
{
	size_t count = max_items;

	if (name != NULL && count != 0) {
		if (
			!ggept_ip_seq_append_net(gs, hseq, NET_TYPE_IPV4,
				name, name_tls, evec, ecnt, &count, cobs)
		) {
			return GGEP_BAD_SIZE;
		}
	}

	g_assert(count <= max_items);
	count = max_items - count;

	if (name6 != NULL && count != 0) {
		if (
			!ggept_ip_seq_append_net(gs, hseq, NET_TYPE_IPV6,
				name6, name6_tls, evec, ecnt, &count, cobs)
		) {
			return GGEP_BAD_SIZE;
		}
	}
	return GGEP_OK;
}

/**
 * Emit vector of IP:port addresses for "IPP".
 *
 * @param gs		the GGEP stream to which extensions are written
 * @param hvec		vector of IP:port (IPv4 and IPv6 mixed)
 * @param hcnt		length of hvec[]
 * @param evec		exclusion address vector
 * @param ecnt		length of evec[]
 * @param add_ipv6	whether IPv6 addresses are requested
 * @param no_ipv4	whether IPv4 addresses should be excluded
 */
ggept_status_t
ggept_ipp_pack(ggep_stream_t *gs, const gnet_host_t *hvec, size_t hcnt,
	const gnet_host_t *evec, size_t ecnt,
	bool add_ipv6, bool no_ipv4)
{
	vector_t v = vector_create(deconstify_pointer(hvec), sizeof *hvec, hcnt);
	sequence_t hseq;

	sequence_fill_from_vector(&hseq, &v);

	return ggept_ip_seq_append(gs, &hseq,
		no_ipv4 ? NULL : GGEP_NAME(IPP), GGEP_NAME(IPP_TLS),
		add_ipv6 ? GGEP_NAME(IPP6) : NULL, GGEP_NAME(IPP6_TLS),
		evec, ecnt, (size_t) -1, FALSE);
}

/**
 * Emit vector of IP:port addresses for "DHTIPP".
 *
 * @param gs		the GGEP stream to which extensions are written
 * @param hvec		vector of IP:port (IPv4 and IPv6 mixed)
 * @param hcnt		length of hvec[]
 * @param add_ipv6	whether IPv6 addresses are requested
 * @param no_ipv4	whether IPv4 addresses should be excluded
 */
ggept_status_t
ggept_dhtipp_pack(ggep_stream_t *gs, const gnet_host_t *hvec, size_t hcnt,
	bool add_ipv6, bool no_ipv4)
{
	vector_t v = vector_create(deconstify_pointer(hvec), sizeof *hvec, hcnt);
	sequence_t hseq;

	sequence_fill_from_vector(&hseq, &v);

	return ggept_ip_seq_append(gs, &hseq,
		no_ipv4 ? NULL : GGEP_NAME(IPP), NULL,
		add_ipv6 ? GGEP_NAME(IPP6) : NULL, NULL,
		NULL, 0, (size_t) -1, FALSE);
}

/**
 * Emit sequence of IP:port addresses for "PUSH".
 *
 * @param gs		the GGEP stream to which extensions are written
 * @param hseq		sequence of IP:port (IPv4 and IPv6 mixed)
 * @param max		maximum amount of entries to add
 * @param flags		a combination of QHIT_F_* flags
 */
ggept_status_t
ggept_push_pack(ggep_stream_t *gs, const sequence_t *hseq, size_t max,
	unsigned flags)
{
	return ggept_ip_seq_append(gs, hseq,
		(flags & QHIT_F_IPV6_ONLY) ? NULL : GGEP_NAME(PUSH),
		GGEP_NAME(PUSH_TLS),
		(flags & QHIT_F_IPV6) ? GGEP_NAME(PUSH6) : NULL, GGEP_NAME(PUSH6_TLS),
		NULL, 0, max, FALSE);
}

/**
 * Emit sequence of IP:port addresses for "A" in HEAD pongs.
 *
 * @param gs		the GGEP stream to which extensions are written
 * @param hvec		vector of IP:port (IPv4 and IPv6 mixed)
 * @param hcnt		length of hvec[]
 */
ggept_status_t
ggept_a_pack(ggep_stream_t *gs, const gnet_host_t *hvec, size_t hcnt)
{
	vector_t v = vector_create(deconstify_pointer(hvec), sizeof *hvec, hcnt);
	sequence_t hseq;

	sequence_fill_from_vector(&hseq, &v);

	return ggept_ip_seq_append(gs, &hseq,
		GGEP_NAME(A), GGEP_NAME(T),
		GGEP_NAME(A6), GGEP_NAME(T6),
		NULL, 0, (size_t) -1, FALSE);
}

/**
 * Emit sequence of IP:port addresses for "ALT" in query hits.
 *
 * @param gs		the GGEP stream to which extensions are written
 * @param hvec		vector of IP:port (IPv4 and IPv6 mixed)
 * @param hcnt		length of hvec[]
 * @param flags		a combination of QHIT_F_* flags
 */
ggept_status_t
ggept_alt_pack(ggep_stream_t *gs, const gnet_host_t *hvec, size_t hcnt,
	unsigned flags)
{
	vector_t v = vector_create(deconstify_pointer(hvec), sizeof *hvec, hcnt);
	sequence_t hseq;

	sequence_fill_from_vector(&hseq, &v);

	/* This needs COBS encoding */

	return ggept_ip_seq_append(gs, &hseq,
		(flags & QHIT_F_IPV6_ONLY) ? NULL : GGEP_NAME(ALT), GGEP_NAME(ALT_TLS),
		(flags & QHIT_F_IPV6) ? GGEP_NAME(ALT6) : NULL, GGEP_NAME(ALT6_TLS),
		NULL, 0, (size_t) -1, TRUE);
}

static ggept_status_t
ggept_ip_vec_extract(const extvec_t *exv,
	gnet_host_vec_t **hvec, enum net_type net)
{
	int len;
	int ilen;

	g_assert(exv);
	g_assert(hvec);
	g_assert(EXT_GGEP == exv->ext_type);
	g_assert(NET_TYPE_IPV4 == net || NET_TYPE_IPV6 == net);

	len = ext_paylen(exv);
	ilen = NET_TYPE_IPV4 == net ? 6 : 18;	/* IP + port */

	if (len <= 0)
		return GGEP_INVALID;

	if (len % ilen != 0)
		return GGEP_INVALID;

	if (hvec) {
		gnet_host_vec_t *vec = *hvec;
		const char *p;
		uint n, i;

		vec = NULL == vec ? gnet_host_vec_alloc() : vec;
		n = len / ilen;
		n = MIN(n, 255);	/* n_ipv4 and n_ipv6 are uint8 */

		g_assert(n > 0);

		if (NET_TYPE_IPV4 == net) {
			if (vec->n_ipv4 != 0)
				return GGEP_DUPLICATE;
			vec->n_ipv4 = n;
			WALLOC_ARRAY(vec->hvec_v4, n);
		} else {
			if (vec->n_ipv6 != 0)
				return GGEP_DUPLICATE;
			vec->n_ipv6 = n;
			WALLOC_ARRAY(vec->hvec_v6, n);
		}

		p = ext_payload(exv);
		for (i = 0; i < n; i++) {
			/* IPv4 address (BE) or IPv6 address (BE) + Port (LE) */
			if (NET_TYPE_IPV4 == net) {
				memcpy(&vec->hvec_v4[i].data, p, 6);
				p += 6;
			} else {
				memcpy(&vec->hvec_v6[i].data, p, 18);
				p += 18;
			}
		}
		*hvec = vec;
	}

	return GGEP_OK;
}

/**
 * Extract vector of IP:port alternate locations.
 *
 * The `hvec' pointer is filled with a dynamically allocated vector.
 * Unless GGEP_OK is returned, no memory allocation takes place.
 *
 * If *hvec is not NULL, it is filled with new hosts provided that there were
 * no hosts for that kind yet within the vector.
 *
 * @param exv	the extension vector
 * @param hvec	pointer is filled with a dynamically allocated vector.
 * @param net	type of network addresses expected in the extension
 *
 * @return GGEP_OK on success
 */
ggept_status_t
ggept_alt_extract(const extvec_t *exv,
	gnet_host_vec_t **hvec, enum net_type net)
{
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_ALT ||
		exv->ext_token == EXT_T_GGEP_ALT6);

	return ggept_ip_vec_extract(exv, hvec, net);
}

/**
 * Extract vector of IP:port push proxy locations.
 *
 * The `hvec' pointer is filled with a dynamically allocated vector.
 * Unless GGEP_OK is returned, no memory allocation takes place.
 *
 * If *hvec is not NULL, it is filled with new hosts provided that there were
 * no hosts for that kind yet within the vector.
 *
 * @param exv	the extension vector
 * @param hvec	pointer is filled with a dynamically allocated vector.
 * @param net	type of network addresses expected in the extension
 *
 * @return GGEP_OK on success
 */
ggept_status_t
ggept_push_extract(const extvec_t *exv,
	gnet_host_vec_t **hvec, enum net_type net)
{
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_PUSH);

	return ggept_ip_vec_extract(exv, hvec, net);
}

/**
 * Extract an UTF-8 encoded string into the supplied buffer.
 *
 * @returns extraction status: only when GGEP_OK is returned will we have
 * extracted something in the supplied buffer.
 */
ggept_status_t
ggept_utf8_string_extract(const extvec_t *exv, char *buf, size_t len)
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
ggept_hname_extract(const extvec_t *exv, char *buf, int len)
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
 * Extract filesize length into `filesize' from extension encoded in variable-
 * length little endian with leading zeroes stripped.
 *
 * This is the format used by the payload of GGEP "LF" for instance.
 */
ggept_status_t
ggept_filesize_extract(const extvec_t *exv, uint64 *filesize)
{
	uint64 fs;
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);

	len = ext_paylen(exv);
	if (len < 1 || len > 8) {
		return GGEP_INVALID;
	}
	fs = vlint_decode(ext_payload(exv), len);
	if (0 == fs) {
		return GGEP_INVALID;
	}
	if (filesize) {
		*filesize = fs;
	}
	return GGEP_OK;
}

/**
 * Extract UNIX timestamp + filesize length into `stamp' and `filesize',
 * reading from the supplied extension payload.
 *
 * This is the format used by the payload of GGEP "PRU" for instance.
 */
ggept_status_t
ggept_stamp_filesize_extract(const extvec_t *exv,
	time_t *stamp, uint64 *filesize)
{
	size_t len;
	const char *p;

	g_assert(exv->ext_type == EXT_GGEP);

	len = ext_paylen(exv);
	if (len < 4 || len > 12)
		return GGEP_INVALID;

	p = ext_payload(exv);
	*stamp = peek_be32(p);
	len -= 4;
	p += 4;
	*filesize = vlint_decode(p, len);		/* Can be zero */

	return GGEP_OK;
}

/**
 * Extract IPv6 address into `addr' from GGEP "GTKG.IPV6" or "6" extensions.
 * When "addr" is NULL, simply validates the payload length.
 */
ggept_status_t
ggept_gtkg_ipv6_extract(const extvec_t *exv, host_addr_t *addr)
{
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_GTKG_IPV6 ||
		exv->ext_token == EXT_T_GGEP_6);

	len = ext_paylen(exv);
	if (0 != len && len < 16)
		return GGEP_INVALID;

	if (addr != NULL) {
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
 * @param len		Length of buffer
 *
 * @return the amount of bytes written.
 */
uint
ggept_filesize_encode(uint64 filesize, char *data, size_t len)
{
	g_assert(len >= 8);

	return vlint_encode(filesize, data);
}

/**
 * Encode `stamp' and `filesize' in buffer.
 *
 * @param stamp		the time to encode
 * @param filesize	the filesize to encode
 * @param data		a buffer of at least 12 bytes.
 * @param len		length of buffer
 *
 * This is used in extensions such as GGEP "PRU" which carry the last
 * modification time and the file length.
 *
 * @return the amount of bytes written
 */
uint
ggept_stamp_filesize_encode(time_t stamp, uint64 filesize,
	char *data, size_t len)
{
	char *p = data;

	g_assert(len >= 12);

	p = poke_be32(p, stamp);
	return 4 + vlint_encode(filesize, p);
}

/**
 * Extract unsigned (32-bit) quantity encoded as variable-length little-endian.
 */
ggept_status_t
ggept_uint32_extract(const extvec_t *exv, uint32 *val)
{
	uint32 v;
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);

	len = ext_paylen(exv);
	if (len > 4) {
		return GGEP_INVALID;
	}
	v = vlint_decode(ext_payload(exv), len);
	if (val != NULL) {
		*val = v;
	}
	return GGEP_OK;
}

/**
 * Extract daily uptime into `uptime', from the GGEP "DU" extensions.
 */
ggept_status_t
ggept_du_extract(const extvec_t *exv, uint32 *uptime)
{
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_DU);

	return ggept_uint32_extract(exv, uptime);
}

/**
 * Encode `uptime' for the GGEP "DU" extension into `data'.
 *
 * @param uptime	the uptime (in seconds) to encode.
 * @param data		a buffer of at least 4 bytes.
 * @param len		buffer length
 *
 * @return the amount of chars written.
 */
uint
ggept_du_encode(uint32 uptime, char *data, size_t len)
{
	g_assert(len >= 4);

	return vlint_encode(uptime, data);
}

/**
 * Encode `media_type' for the GGEP "M" extension into `data'.
 *
 * @param mtype		the media type mask
 * @param data		a buffer of at least 4 bytes.
 * @param len		buffer length
 *
 * @return the amount of chars written.
 */
uint
ggept_m_encode(uint32 mtype, char *data, size_t len)
{
	g_assert(len >= 4);

	return vlint_encode(mtype, data);
}

ggept_status_t
ggept_ct_extract(const extvec_t *exv, time_t *stamp_ptr)
{
	uint64 v;
	size_t len;

	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(exv->ext_token == EXT_T_GGEP_CT);

	len = ext_paylen(exv);
	if (len > 8) {
		return GGEP_INVALID;
	}
	v = vlint_decode(ext_payload(exv), len);
	if (stamp_ptr) {
		*stamp_ptr = MIN(v, TIME_T_MAX);
	}
	return GGEP_OK;
}

/**
 * Encode `timestamp' for the GGEP "CT" extension into `data'.
 *
 * @param timestamp	the timestamp (seconds since Epoch) to encode.
 * @param data		a buffer of at least 8 bytes.
 * @param len		buffer length
 *
 * @return the amount of chars written.
 */
uint
ggept_ct_encode(time_t timestamp, char *data, size_t len)
{
	g_assert(len >= 4);

	return vlint_encode(timestamp, data);
}

/* vi: set ts=4 sw=4 cindent: */
