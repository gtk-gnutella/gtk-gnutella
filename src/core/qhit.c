/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * Query hit packet management.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "qhit.h"
#include "bsched.h"
#include "dmesh.h"		/* For dmesh_fill_alternate() */
#include "ggep.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "gnutella.h"
#include "ipp_cache.h"
#include "ipv6-ready.h"
#include "nodes.h"
#include "search.h"		/* For QUERY_FW2FW_FILE_INDEX */
#include "settings.h"	/* For listen_ip() */
#include "share.h"
#include "sockets.h"	/* For socket_listen_port() */
#include "uploads.h"	/* For count_uploads */
#include "version.h"	/* For version_get_commit() and version_is_dirty() */

#include "if/gnet_property_priv.h"
#include "if/core/main.h"			/* For main_get_build() */

#include "lib/array.h"
#include "lib/endian.h"
#include "lib/getdate.h"
#include "lib/hashing.h"
#include "lib/hset.h"
#include "lib/product.h"
#include "lib/random.h"
#include "lib/sequence.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"			/* Must be the last header included */

/*
 * NOTE: LimeWire doesn't like more than 10 results per QHIT packet or
 *       more than 10 alt-locs per QHIT packet.
 */
#define QHIT_MAX_RESULTS	10		/**< Maximum amount of hits in a query hit */
#define QHIT_MAX_ALT		10		/**< Send out 10 alt-locs per entry, max */
#define QHIT_MAX_PROXIES	8		/**< Send out 8 push-proxies at most */
#define QHIT_MAX_GGEP		512		/**< Allocated room for trailing GGEP */
#define QHIT_SIZE_THRESHOLD	2016	/**< Flush query hits larger than this */

/*
 * Minimal trailer length is our code NAME, the open flags, and the GUID.
 */
#define QHIT_MIN_TRAILER_LEN	(4+3+16)	/**< NAME + open flags + GUID */

/*
 * Buffer where query hit packet is built.
 *
 * There is only one such packet, a static buffer.  At the beginning, one
 * founds the gnutella header, followed by the query hit header: initial
 * offsetting set by found_clear().
 *		--RAM, 25/09/2001
 */

struct found_struct {
	char data[64 * 1024];		/**< data */
	size_t pos;					/**< current write position */
	size_t files;				/**< amount of file entries */
	size_t max_size;			/**< max query hit size */
	const struct guid *muid;	/**< the MUID to put in all query hits */
	const struct array *token;	/**< Optional secure OOB token */
	hset_t *hs;					/**< Records file indices and SHA1 atoms */
	qhit_process_t process;		/**< processor once query hit is built */
	void *udata;				/**< processor argument */
	unsigned flags;				/**< Set of QHIT_F_* flags */
	unsigned open:1;			/**< Set if found_open() was used */
};

static struct found_struct *
found_get(void)
{
	static struct found_struct found_data;
	return &found_data;
}

static size_t
found_file_count(void)
{
	return found_get()->files;
}

static size_t
found_max_size(void)
{
	return found_get()->max_size;
}

static void
found_add_files(size_t n)
{
	found_get()->files += n;
}

static bool
found_ggep_h(void)
{
	return booleanize(found_get()->flags & QHIT_F_GGEP_H);
}

static unsigned
found_flags(void)
{
	return found_get()->flags;
}

static char *
found_open(void)
{
	struct found_struct *f = found_get();

	g_assert(!f->open);
	f->open = TRUE;
	g_assert(f->pos <= sizeof f->data);
	return &f->data[f->pos];
}

static host_addr_t
found_listen_addr(void)
{
	host_addr_t ha = listen_addr_primary();

	/* IPv6-Ready */

	if ((found_flags() & QHIT_F_IPV6_ONLY) && !host_addr_is_ipv6(ha)) {
		host_addr_t ha6 = listen_addr6();
		return is_host_addr(ha6) ? ha6 : ha;
	}

	return ha;
}

static void
found_close(size_t len)
{
	struct found_struct *f = found_get();

	g_assert(f->open);
	g_assert(f->pos <= sizeof f->data);
	g_assert(len <= sizeof f->data - f->pos);
	f->pos += len;
	f->open = FALSE;
}

static size_t
found_size(void)
{
	struct found_struct *f = found_get();

	g_assert(!f->open);
	g_assert(f->pos <= sizeof f->data);
	return f->pos;
}

static size_t
found_left(void)
{
	struct found_struct *f = found_get();

	g_assert(!f->open);
	g_assert(f->pos <= sizeof f->data);
	return sizeof f->data - f->pos;
}

static bool
found_write(const void *data, size_t length)
{
	struct found_struct *f = found_get();

	g_assert(data != NULL);
	g_assert(length != 0);
	g_assert(length <= INT_MAX);
	g_assert(!f->open);

	if (length > sizeof f->data - f->pos)
		return FALSE;

	g_assert(f->pos < sizeof f->data);
	memcpy(&f->data[f->pos], data, length);
	f->pos += length;
	g_assert(f->pos >= length && f->pos <= sizeof f->data);
	return TRUE;
}

static void
found_set_header(void)
{
	struct found_struct *f = found_get();
	gnutella_msg_search_results_t *msg;
	uint32 connect_speed;		/* Connection speed, in kbits/s */
	uint32 ipv4;
	size_t len;

	g_assert(!f->open);
	g_assert(f->pos >= GTA_HEADER_SIZE);
	len = f->pos - GTA_HEADER_SIZE;
	g_assert(len < sizeof f->data);

	msg = (gnutella_msg_search_results_t *) f->data;

	{
		gnutella_header_t *header = gnutella_msg_search_results_header(msg);

		gnutella_header_set_muid(header, f->muid);
		gnutella_header_set_function(header, GTA_MSG_SEARCH_RESULTS);
		/* The TTL is overridden later if sending inbound */
		gnutella_header_set_ttl(header, 1);
		gnutella_header_set_hops(header, 0);
		gnutella_header_set_size(header, len);
	}

	gnutella_msg_search_results_set_num_recs(msg, f->files); /* One byte */

	/*
	 * Compute connection speed dynamically if requested.
	 */

	connect_speed = GNET_PROPERTY(connection_speed);
	if (GNET_PROPERTY(compute_connection_speed)) {
		if (GNET_PROPERTY(max_uploads) > 0) {
			connect_speed = bsched_avg_bps(BSCHED_BWS_OUT);
			connect_speed = MAX(connect_speed,
								bsched_bw_per_second(BSCHED_BWS_OUT));
			connect_speed /= 1024 / 8;
			if (connect_speed == 0) {
				/* No b/w limit set and no traffic yet */
				connect_speed = 32;
			}
		} else {
			connect_speed = 0;
		}
	}
	/* Upload speed expected per slot */
	connect_speed /= MAX(1, GNET_PROPERTY(max_uploads));

	/*
	 * IPv6-Ready support: the QHIT message is architected with an IPv4 address.
	 * When the address we want to send is an IPv6 one, it needs to be sent
	 * in a GGEP "6" field and the IPv4 field be set to 127.0.0.0.
	 */

	ipv4 = ipv6_ready_advertised_ipv4(found_listen_addr());

	gnutella_msg_search_results_set_host_port(msg, socket_listen_port());
	gnutella_msg_search_results_set_host_ip(msg, ipv4);
	gnutella_msg_search_results_set_host_speed(msg, connect_speed);
}

static void
found_clear(void)
{
	struct found_struct *f = found_get();

	f->pos = GTA_HEADER_SIZE + sizeof(gnutella_search_results_t);
	g_assert(f->pos > 0 && f->pos < sizeof f->data);
	f->files = 0;
	f->open = FALSE;
}

static void
found_process(void)
{
	struct found_struct *f = found_get();

	g_assert(f->process != NULL);
	f->process(f->data, f->pos, f->udata);
}

static const struct array *
found_token(void)
{
	struct found_struct *f = found_get();
	return f->token;
}

static void
found_init(size_t max_size, const struct guid *xuid, unsigned flags,
	qhit_process_t proc, void *udata, const struct array *token)
{
	struct found_struct *f = found_get();

	g_assert(max_size <= INT_MAX);
	g_assert(xuid != NULL);
	g_assert(proc != NULL);
	g_assert(token != NULL);
	g_assert(NULL == f->hs);

	f->max_size = max_size;
	f->muid = xuid;
	f->flags = flags;
	f->process = proc;
	f->udata = udata;
	f->open = FALSE;
	f->token = token;
	f->hs = hset_create(HASH_KEY_SELF, 0);
}

static void
found_done(void)
{
	struct found_struct *f = found_get();

	hset_free_null(&f->hs);
}

static bool
found_contains(const void *key)
{
	struct found_struct *f = found_get();

	return hset_contains(f->hs, key);
}

static size_t
found_contains_count(void)
{
	struct found_struct *f = found_get();

	return hset_count(f->hs);
}

static void
found_insert(const void *key)
{
	struct found_struct *f = found_get();

	hset_insert(f->hs, key);
}

static time_t release_date;

/**
 * Processor for query hits sent inbound.
 */
static void
qhit_send_node(void *data, size_t len, void *udata)
{
	gnutella_node_t *n = udata;
	gnutella_header_t *packet_head = data;
	uint ttl;

	if (GNET_PROPERTY(dbg) > 3) {
		g_debug("flushing query hit (%u entr%s, %u bytes sofar) to %s",
			(uint) found_file_count(), plural_y(found_file_count()),
			(uint) found_size(),
			node_addr(n));
	}

	g_assert(len <= INT_MAX);

	/*
	 * We limit the TTL to the minimal possible value, then add a margin
	 * of 5 to account for re-routing abilities some day.  We then trim
	 * at our configured hard TTL limit.  Replies are precious packets,
	 * it would be a pity if they did not make it back to their source.
	 *
	 *			 --RAM, 02/02/2001
	 */

	if (gnutella_header_get_hops(&n->header) == 0) {
		g_warning("qhit_send_node(): hops=0, bug in route_message()?");
		/* Can't send message with TTL=0 */
		gnutella_header_set_hops(&n->header, 1);
	}

	ttl = gnutella_header_get_hops(&n->header) + 5U;
	ttl = MIN(ttl, GNET_PROPERTY(hard_ttl_limit));
	gnutella_header_set_ttl(packet_head, ttl);

	gmsg_sendto_one(n, data, len);
}

static void
qhit_log_ggep_write_failure(const char *id)
{
	if (GNET_PROPERTY(qhit_debug)) {
		g_warning("QHIT could not write GGEP \"%s\" extension: %s",
			id, ggep_errstr());
	}
}

/**
 * Flush pending search request to the network.
 */
static void
flush_match(void)
{
	char trailer[7];
	int ggep_len = 0;			/* Size of the GGEP trailer */
	ggep_stream_t gs;
	char *trailer_start;

	/*
	 * Build gtk-gnutella trailer.
	 * It is compatible with BearShare's one in the "open data" section.
	 */

	memcpy(trailer, "GTKG", 4);	/* Vendor code */
	trailer[4] = 2;					/* Open data size */
	trailer[5] = 0x04 | 0x08 | 0x20;	/* Valid flags we set */
	trailer[6] = 0x01;				/* Our flags (valid firewall bit) */

	if (GNET_PROPERTY(ul_running) >= GNET_PROPERTY(max_uploads))
		trailer[6] |= 0x04;			/* Busy flag */
	if (GNET_PROPERTY(total_uploads) > 0)
		trailer[6] |= 0x08;			/* One file uploaded, at least */
	if (GNET_PROPERTY(is_firewalled))
		trailer[5] |= 0x01;			/* Firewall bit set in enabling byte */

	/*
	 * Store the open trailer, and remember where we store it, so we can
	 * update the flags if we store any GGEP extension.
	 */

	trailer_start = found_open();
	found_close(0);	/* Nothing written */

	if (!found_write(trailer, sizeof trailer)) /* Store the open trailer */
		goto failure;

	/*
	 * Ensure we can stuff at most QHIT_MAX_GGEP bytes of GGEP trailer.
	 */

	if (found_left() < QHIT_MAX_GGEP)
		goto failure;

	g_assert(QHIT_MAX_GGEP <= found_left());
	ggep_stream_init(&gs, found_open(), QHIT_MAX_GGEP);

	/*
	 * Build the "GTKGV" GGEP extension.
	 */

	{
		uint8 major = product_get_major();
		uint8 minor = product_get_minor();
		uint8 revchar = product_get_revchar();
		uint8 patch = product_get_patchlevel();
		uint32 release;
		uint32 date = release_date;
		uint32 build;
		uint8 version = 1;		/* This is GTKGV version 1 */
		uint8 osname;
		uint8 flags;
		uint8 commit_len;
		size_t commit_bytes;
		const sha1_t *commit;
		bool ok;

		flags = GTKGV_F_GIT | GTKGV_F_OS;
		if (version_is_dirty())
			flags |= GTKGV_F_DIRTY;

		poke_be32(&release, date);
		poke_be32(&build, product_get_build());

		commit = version_get_commit(&commit_len);
		commit_bytes = (1 + commit_len) / 2;
		osname = ggept_gtkgv_osname_value();

		ok =
			ggep_stream_begin(&gs, GGEP_NAME(GTKGV), 0) &&
			ggep_stream_write(&gs, &version, 1) &&
			ggep_stream_write(&gs, &major, 1) &&
			ggep_stream_write(&gs, &minor, 1) &&
			ggep_stream_write(&gs, &patch, 1) &&
			ggep_stream_write(&gs, &revchar, 1) &&
			ggep_stream_write(&gs, &release, 4) &&
			ggep_stream_write(&gs, &build, 4) &&
			ggep_stream_write(&gs, &flags, 1) &&
			ggep_stream_write(&gs, &commit_len, 1) &&
			ggep_stream_write(&gs, commit, commit_bytes) &&
			ggep_stream_write(&gs, &osname, 1) &&
			ggep_stream_end(&gs);

		if (!ok)
			qhit_log_ggep_write_failure("GTKGV");
	}

	{
		const struct array *token = found_token();
		
		if (
			token->data &&
			!ggep_stream_pack(&gs, GGEP_NAME(SO), token->data, token->size, 0)
		) {
			qhit_log_ggep_write_failure("SO");
		}
	}

	/*
	 * Look whether we'll need a "PUSH" GGEP extension to give out
	 * our current push proxies.
	 */

	if (GNET_PROPERTY(is_firewalled)) {
		sequence_t *seq = node_push_proxies();
		unsigned flags = found_flags();

		if (GGEP_OK != ggept_push_pack(&gs, seq, QHIT_MAX_PROXIES, flags))
			qhit_log_ggep_write_failure("PUSH");
		sequence_release(&seq);
	}

	/*
	 * Look whether we can include an HNAME extension advertising the
	 * server's hostname.
	 */

	if (
		!GNET_PROPERTY(is_firewalled) &&
		GNET_PROPERTY(give_server_hostname) &&
		!is_null_or_empty(GNET_PROPERTY(server_hostname))
	) {
		bool ok;

		ok = ggep_stream_pack(&gs, GGEP_NAME(HNAME),
				GNET_PROPERTY(server_hostname),
				strlen(GNET_PROPERTY(server_hostname)),
				0);

		if (!ok)
			qhit_log_ggep_write_failure("HNAME");
	}

	/*
	 * IPv6-Ready support: if our primary listening address is IPv6, then emit
	 * the GGEP "6" extension.  Likewise if we are also listening on IPv6.
	 */

	{
		host_addr_t addr;
		host_addr_t ipv6;

		addr = found_listen_addr();

		ipv6 = host_addr_is_ipv6(addr) ? addr : listen_addr6();

		if (is_host_addr(ipv6) && host_addr_is_ipv6(ipv6)) {
			const uint8 *data = host_addr_ipv6(&ipv6);
			if (!ggep_stream_pack(&gs, GGEP_NAME(6), data, 16, 0))
				qhit_log_ggep_write_failure("6");
		}
	}

	if (tls_enabled()) {
		if (!ggep_stream_pack(&gs, GGEP_NAME(TLS), NULL, 0, 0))
			qhit_log_ggep_write_failure("TLS");
	}

	/*
	 * Advertise the Browse Host extension in the results if the feature is
	 * enabled.
     */

	if (GNET_PROPERTY(browse_host_enabled)) {
		if (!ggep_stream_pack(&gs, GGEP_NAME(BH), NULL, 0, 0))
			qhit_log_ggep_write_failure("BH");
	}

	ggep_len = ggep_stream_close(&gs);
	found_close(ggep_len);

	if (ggep_len > 0)
		trailer_start[6] |= 0x20;		/* Has GGEP extensions in trailer */

	/*
	 * Store the GUID in the last 16 bytes of the query hit.
	 */

	if (!found_write(GNET_PROPERTY(servent_guid), GUID_RAW_SIZE))
		goto failure;

	found_set_header();
	found_process();
	return;

failure:

	if (GNET_PROPERTY(qhit_debug))
		g_warning("QHIT message was too big, discarding");

	found_clear();
}

/**
 * Add file to current query hit.
 *
 * @returns TRUE if we inserted the record, FALSE if we refused it due to
 * lack of space.
 */
static bool
add_file(const shared_file_t *sf)
{
	bool sha1_available;
	gnet_host_t hvec[QHIT_MAX_ALT];
	int hcnt = 0;
	uint32 fs32, fs32_le, idx_le;
	int ggep_len;
	bool ok;
	ggep_stream_t gs;
	size_t left, needed;
	void *start;
	bool is_partial;
	uint32 file_index;

	is_partial = shared_file_is_partial(sf);
	needed = 8 + 2 + shared_file_name_nfc_len(sf);	/* size of hit entry */
	sha1_available = sha1_hash_available(sf);

	g_return_val_unless(!is_partial || sha1_available, FALSE);

	/*
	 * Make sure we never insert duplicate indices in a query hit.
	 *
	 * This code assumes there will never be any collision between shared
	 * file indices and pointers to SHA1, which will always hold fortunately
	 * in real life.
	 */

	file_index = shared_file_index(sf);

	if (!is_partial) {
		g_assert_log(
			!found_contains(uint_to_pointer(file_index)),
			"file_index=%u (%s SHA1), qhit_contains=%zu, qhit_files=%zu",
			(unsigned) file_index, sha1_available ? "has" : "no",
			found_contains_count(), found_file_count());
	} else {
		unsigned i;

		/*
		 * Generate a random file index, unique to this query hit.
		 *
		 * This is for the sake of our own spam detector which will
		 * frown upon duplicate file indices.
		 */

		for (i = 0; i < 100; i++) {
			file_index = 1 + random_value(INT_MAX - 1);

			if (QUERY_FW2FW_FILE_INDEX == file_index)
				continue;

			if (!found_contains(uint_to_pointer(file_index)))
				goto unique_file_index;
		}
		g_error("no luck with random number generator");
	}

unique_file_index:
	found_insert(uint_to_pointer(file_index));

	/*
	 * In case we emit the SHA1 as a GGEP "H", we'll grow the buffer
	 * larger necessary, since the extension will take at most 26 bytes,
	 * and could take only 25.  This is NOT a problem, as we later adjust
	 * the real size to fit the data we really emitted.
	 *
	 * If some alternate locations are available, they'll be included as
	 * GGEP "ALT" afterwards.
	 */

	if (sha1_available) {
		const sha1_t *sha1 = shared_file_sha1(sf);

		/*
		 * They can share twice or more identical files.  Make sure we only
		 * include each SHA1 once in the query hits we return for a query:
		 * having multiple entries would waste bandwidth anyway.
		 */

		if (found_contains(sha1)) {
			if (GNET_PROPERTY(qhit_debug))
				g_warning("QHIT not including SHA1 %s twice",
					sha1_base32(sha1));
			return TRUE;		/* Entry consumed, but not included */
		}

		found_insert(sha1);		/* SHA1 are atoms, address is unique */

		needed += 9 + SHA1_BASE32_SIZE;
		hcnt = dmesh_fill_alternate(sha1, hvec, G_N_ELEMENTS(hvec));
		needed += hcnt * 18 + 6;	/* Conservative, assumes IPv6 only */
	}

	/*
	 * Refuse entry if we don't have enough room.	-- RAM, 22/01/2002
	 */

	if (
		found_size() + needed + QHIT_MIN_TRAILER_LEN
			> GNET_PROPERTY(search_answers_forward_size)
	)
		return FALSE;

	/*
	 * Grow buffer by the size of the search results header 8 bytes,
	 * plus the string length - NULL, plus two NULL's
	 */

	if (needed > found_left())
		return FALSE;

	/*
	 * If size is greater than 2^31-1, we store ~0 as the file size and will
	 * use the "LF" GGEP extension to hold the real size.
	 */

	fs32 = shared_file_size(sf) >= (1U << 31) ? ~0U : shared_file_size(sf);

	poke_le32(&idx_le, file_index);
	if (!found_write(&idx_le, sizeof idx_le))
		return FALSE;
	poke_le32(&fs32_le, fs32);
	if (!found_write(&fs32_le, sizeof fs32_le))
		return FALSE;
	if (!found_write(shared_file_name_nfc(sf), shared_file_name_nfc_len(sf)))
		return FALSE;

	/* Position equals the next byte to be written to */

	if (!found_write("", 1))
		return FALSE;

	/*
	 * We're now between the two NULs at the end of the hit entry.
	 */

	/*
	 * Emit the SHA1 as a plain ASCII URN if they don't grok "H".
	 */

	if (sha1_available && !found_ggep_h()) {
		const struct sha1 * const sha1 = shared_file_sha1(sf);

		/* Good old way: ASCII URN */
		if (!found_write(sha1_to_urn_string(sha1), SHA1_URN_LENGTH))
			return FALSE;
		if (!found_write("\x1c", 1))
			return FALSE;
	}

	/*
	 * From now on, we emit GGEP extensions, if we emit at all.
	 */

	left = found_left();
	start = found_open();
	ggep_stream_init(&gs, start, left);

	/*
	 * If we matched a partial file, let them know (unless the file is
	 * being seeded, in which case it is really complete).
	 *
	 * For now we don't emit the available ranges (need to build the tree
	 * of 1 KiB blocks and send numbers of the highest node in the tree
	 * encompassing an available chunk) in PR0, PR1, PR2, PR3 or PR4 keys.
	 *
	 * We just emit the "PRU" key, signaling that it's a partial result
	 * and that its data is still unverified (since we don't verify available
	 * chunks using the TTH for now).
	 *		--RAM, 2011-05-15
	 */

	if (is_partial && !shared_file_is_finished(sf)) {
		time_t mtime = shared_file_modification_time(sf);
		filesize_t available = shared_file_available(sf);
		char buf[sizeof mtime + sizeof available];
		uint len;

		/*
		 * Starting with 0.98.4, we emit a payload in the "PRU" key to indicate
		 * the last modification time of the file and the amount of bytes
		 * available on the server.		--RAM, 2012-11-03
		 */

		len = ggept_stamp_filesize_encode(mtime, available, buf, sizeof buf);
		ok = ggep_stream_pack(&gs, GGEP_NAME(PRU), buf, len, GGEP_W_COBS);
		if (!ok)
			qhit_log_ggep_write_failure("PRU");
	}

	/*
	 * Emit the SHA1 as GGEP "H" if they said they understand it. The modern
	 * way is GGEP "H" for binary URN but only gtk-gnutella implements it.
	 */

	if (sha1_available && found_ggep_h()) {
		const struct sha1 * const sha1 = shared_file_sha1(sf);
		const struct tth * const tth = shared_file_tth(sf);
		const uint8 type = tth ? GGEP_H_BITPRINT : GGEP_H_SHA1;

		ok =
			ggep_stream_begin(&gs, GGEP_NAME(H), GGEP_W_COBS) &&
			ggep_stream_write(&gs, &type, 1) &&
			ggep_stream_write(&gs, sha1->data, SHA1_RAW_SIZE) &&
			(tth ? ggep_stream_write(&gs, tth->data, TTH_RAW_SIZE) : TRUE) &&
			ggep_stream_end(&gs);

		if (!ok)
			qhit_log_ggep_write_failure("H");
	}

	/*
	 * First LimeWire emitted TTHs as plain text urn:ttroot:<base32 TTH>.
	 * Now they are still unaware of GGEP "H" but emit GGEP "TT" with the
	 * hash in binary form.
	 */

	if (sha1_available && !found_ggep_h()) {
		const struct tth * const tth = shared_file_tth(sf);

		if (tth) {
			ok = ggep_stream_pack(&gs,
						GGEP_NAME(TT), tth->data, TTH_RAW_SIZE, GGEP_W_COBS);
			if (!ok)
				qhit_log_ggep_write_failure("TT");
		}
	}

	/*
	 * If the 32-bit size is the magic ~0 escape value, we need to emit
	 * the real size in the "LF" extension.
	 */

	if (fs32 == ~0U) {
		char buf[sizeof(uint64)];
		int len;

		len = ggept_filesize_encode(shared_file_size(sf), buf, sizeof buf);

		g_assert(len > 0 && UNSIGNED(len) <= sizeof buf);

		ok = ggep_stream_pack(&gs, GGEP_NAME(LF), buf, len, GGEP_W_COBS);
		if (!ok)
			qhit_log_ggep_write_failure("LF");
	}

	/*
	 * If we have known alternate locations, include a few of them for
	 * this file in the GGEP "ALT" extension.
	 */

	if (hcnt > 0) {
		unsigned flags = found_flags();

		g_assert(hcnt <= QHIT_MAX_ALT);

		if (GGEP_OK != ggept_alt_pack(&gs, hvec, hcnt, flags))
			qhit_log_ggep_write_failure("ALT");
	}

	{
		const char *rp = shared_file_relative_path(sf);
		
		if (rp) {
			ok = ggep_stream_pack(&gs, GGEP_NAME(PATH), rp, strlen(rp), 0);
			if (!ok)
				qhit_log_ggep_write_failure("PATH");
		}
	}

	{
		time_t create_time;	

		create_time = shared_file_creation_time(sf);
		if ((time_t) -1 != create_time) {
			char buf[sizeof(uint64)];
			int len;

			/*
			 * Suppress negative values (if time_t is signed) as this would
			 * be interpreted as a date far in this future.
			 */
			create_time = MAX(0, create_time);

			len = ggept_ct_encode(create_time, buf, sizeof buf);
			g_assert(UNSIGNED(len) <= sizeof buf);

			ok = ggep_stream_pack(&gs, GGEP_NAME(CT), buf, len, GGEP_W_COBS);
			if (!ok)
				qhit_log_ggep_write_failure("CT");
		}
	}

	/*
	 * Because we don't know exactly the size of the GGEP extension
	 * (could be COBS-encoded or not), we need to adjust the real
	 * extension size now that the entry is fully written.
	 */

	ggep_len = ggep_stream_close(&gs);
	found_close(ggep_len);

	if (!found_write("", 1))		/* Append terminating NUL */
		return FALSE;

	found_add_files(1);

	/*
	 * If we have reached our size limit for query hits, flush what
	 * we have so far.
	 */

	if (
		found_size() >= found_max_size() ||
		found_file_count() >= QHIT_MAX_RESULTS
	) {
		flush_match();
		found_clear();
	}

	return TRUE;		/* Hit entry accepted */
}

/**
 * Reset the QueryHit, that is, the "data found" pointer is at the beginning of
 * the data found section in the query hit packet.
 *
 * @param max_size the maximum size in bytes of individual query hits
 *
 * @param muid is the MUID that should be put in all the generated hits.
 * This must point to a memory location that is guaranteed to stay accurate
 * during all the processing.
 *
 * @param process the processor callback to invoke on each individually built
 * query hit message, along with `udata'.
 *
 * @param udata the node that issued the query hit and to which we must reply
 * for inbound query hit processor, an OOB holding structure when the hits
 * have to be sent out-of-bound
 */
static void
found_reset(size_t max_size, const struct guid *muid, unsigned flags,
	qhit_process_t process, void *udata, const struct array *token)
{
	g_assert(process != NULL);
	g_assert(max_size <= INT_MAX);
	found_init(max_size, muid, flags, process, udata, token);
	found_clear();
}

/**
 * Send as many small query hit packets as necessary to hold the `count'
 * results held in the `files' list.
 *
 * @param n				the node where we should send results to
 * @param files			the list of shared_file_t entries that make up results
 * @param count			the amount of results
 * @param muid			the query's MUID
 * @param flags			a combination of QHIT_F_* flags
 */
void
qhit_send_results(struct gnutella_node *n, GSList *files, int count,
	const struct guid *muid, unsigned flags)
{
	GSList *sl;
	int sent = 0;

	/*
	 * We can't use n->header.muid as the query's MUID but must rely on the
	 * parameter we're given.  Indeed, we're delivering a local hit here,
	 * but the query can have been OOB-proxified already and therefore the
	 * n->header.muid data have been mangled (since that is what we're going
	 * to forward to other nodes).
	 */

	found_reset(QHIT_SIZE_THRESHOLD, muid, flags, qhit_send_node, n,
		&zero_array);

	for (sl = files; sl; sl = g_slist_next(sl)) {
		shared_file_t *sf = sl->data;
		if (add_file(sf))
			sent++;
		shared_file_unref(&sf);
	}

	if (0 != found_file_count())	/* Still some unflushed results */
		flush_match();				/* Send last packet */

	g_slist_free(files);

	if (GNET_PROPERTY(dbg) > 3)
		g_debug("sent %d/%d hits to %s", sent, count, node_addr(n));

	found_done();
}

/**
 * Build query hit results for later delivery.
 *
 * Results are held in the `files' list.  They are packed in hits until
 * the message reaches the `max_msgsize' limit at which time the packet
 * is flushed and given the the `cb' callback for processing (sending,
 * queueing, whatever).
 *
 * The callback is invoked as
 *
 *		cb(data, len, udata)
 *
 * where the query hit message is held in the `len' bytes starting at `data'.
 * The `udata' parameter is simply user-supplied data, opaque for us.
 *
 * @param files			the list of shared_file_t entries that make up results
 * @param count			the amount of results to deliver (first `count' files)
 * @param max_msgsize	the targeted maximum hit size before flushing
 * @param cb			the processor callback to invoke on each built hit
 * @param udata			argument to pass to callback
 * @param muid			the MUID to use on each generated hit
 * @param flags			a combination of QHIT_F_* flags
 * @param token			secure OOBv3 token to include in reply
 */
void
qhit_build_results(const GSList *files, int count, size_t max_msgsize,
	qhit_process_t cb, void *udata, const struct guid *muid, unsigned flags,
	const struct array *token)
{
	const GSList *sl;
	int sent;

	g_assert(cb != NULL);
	g_assert(token);

	found_reset(max_msgsize, muid, flags, cb, udata, token);

	for (sl = files, sent = 0; sl && sent < count; sl = g_slist_next(sl)) {
		const shared_file_t *sf = sl->data;

		if (add_file(sf))
			sent++;
	}

	if (0 != found_file_count())	/* Still some unflushed results */
		flush_match();				/* Send last packet */

	found_done();

	/*
	 * Nothing to free, since everything is the property of the calling module.
	 */
}

/**
 * Initialization of the query hit generation.
 */
void
qhit_init(void)
{
	release_date = date2time(product_get_date(), tm_time());
}

/**
 * Shutdown cleanup.
 */
void
qhit_close(void)
{
	/* Nada */
}

/* vi: set ts=4 sw=4 cindent: */
