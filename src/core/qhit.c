/*
 * $Id$
 *
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

RCSID("$Id$")

#include "qhit.h"
#include "gnutella.h"
#include "ggep.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "share.h"
#include "nodes.h"
#include "bsched.h"
#include "dmesh.h"		/* For dmesh_fill_alternate() */
#include "uploads.h"	/* For count_uploads */
#include "settings.h"	/* For listen_ip() */

#include "if/gnet_property_priv.h"
#include "if/core/main.h"			/* For main_get_build() */

#include "lib/array.h"
#include "lib/getdate.h"
#include "lib/endian.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/override.h"			/* Must be the last header included */

#define QHIT_SIZE_THRESHOLD	2016	/**< Flush query hits larger than this */
#define QHIT_MAX_RESULTS	255		/**< Maximum amount of hits in a query hit */
#define QHIT_MAX_ALT		15		/**< Send out 15 alt-locs per entry, max */
#define QHIT_MAX_PROXIES	5		/**< Send out 5 push-proxies at most */
#define QHIT_MAX_GGEP		512		/**< Allocated room for trailing GGEP */

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
	gchar data[64 * 1024];		/**< data */
	size_t pos;					/**< current write position */
	size_t files;				/**< amount of file entries */
	size_t max_size;			/**< max query hit size */
	const gchar *muid;			/**< the MUID to put in all query hits */
	const struct array *token;	/**< Optional secure OOB token */
	qhit_process_t process;		/**< processor once query hit is built */
	gpointer udata;				/**< processor argument */
	gboolean open;				/**< Set if found_open() was used */
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

static gchar *
found_open(void)
{
	struct found_struct *f = found_get();

	g_assert(!f->open);
	f->open = TRUE;
	g_assert(f->pos <= sizeof f->data);
	return &f->data[f->pos];
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

static gboolean
found_write(gconstpointer data, size_t length)
{
	struct found_struct *f = found_get();

	g_assert(data != NULL);
	g_assert(length != 0);
	g_assert(length <= INT_MAX);
	g_assert(!f->open);

	if (length > sizeof f->data - f->pos) {
		return FALSE;
	}

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
	guint32 connect_speed;		/* Connection speed, in kbits/s */
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
		/* The TTL is overriden later if sending inbound */
		gnutella_header_set_ttl(header, 1);
		gnutella_header_set_hops(header, 0);
		gnutella_header_set_size(header, len);
	}

	gnutella_msg_search_results_set_num_recs(msg, f->files); /* One byte */

	/*
	 * Compute connection speed dynamically if requested.
	 */

	connect_speed = connection_speed;
	if (compute_connection_speed) {
		if (max_uploads > 0) {
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
	connect_speed /= MAX(1, max_uploads);	/* Upload speed expected per slot */

	gnutella_msg_search_results_set_host_port(msg, socket_listen_port());
	gnutella_msg_search_results_set_host_ip(msg, host_addr_ipv4(listen_addr()));
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
found_init(size_t max_size, const gchar *xuid,
	qhit_process_t proc, gpointer udata, const struct array *token)
{
	struct found_struct *f = found_get();

	g_assert(max_size <= INT_MAX);
	g_assert(xuid != NULL);
	g_assert(proc != NULL);
	g_assert(token != NULL);

	f->max_size = max_size;
	f->muid = xuid;
	f->process = proc;
	f->udata = udata;
	f->open = FALSE;
	f->token = token;
}

static time_t release_date;

/**
 * Processor for query hits sent inbound.
 */
static void
qhit_send_node(gpointer data, size_t len, gpointer udata)
{
	gnutella_node_t *n = udata;
	gnutella_header_t *packet_head = data;

	if (dbg > 3) {
		g_message("flushing query hit (%u entr%s, %u bytes sofar) to %s\n",
			(guint) found_file_count(),
			found_file_count() == 1 ? "y" : "ies",
			(guint) found_size(),
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

	gnutella_header_set_ttl(packet_head,
		MIN((guint) gnutella_header_get_hops(&n->header) + 5, hard_ttl_limit));

	gmsg_sendto_one(n, data, len);
}

/**
 * Flush pending search request to the network.
 */
static void
flush_match(void)
{
	gchar trailer[7];
	gint ggep_len = 0;			/* Size of the GGEP trailer */
	ggep_stream_t gs;
	gchar *trailer_start;

	/*
	 * Build gtk-gnutella trailer.
	 * It is compatible with BearShare's one in the "open data" section.
	 */

	memcpy(trailer, "GTKG", 4);	/* Vendor code */
	trailer[4] = 2;					/* Open data size */
	trailer[5] = 0x04 | 0x08 | 0x20;	/* Valid flags we set */
	trailer[6] = 0x01;				/* Our flags (valid firewall bit) */

	if (ul_running >= max_uploads)
		trailer[6] |= 0x04;			/* Busy flag */
	if (total_uploads > 0)
		trailer[6] |= 0x08;			/* One file uploaded, at least */
	if (is_firewalled)
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
	 * Build the "GTKGV1" GGEP extension.
	 */

	{
		guint8 major = GTA_VERSION;
		guint8 minor = GTA_SUBVERSION;
		const gchar *revp = GTA_REVCHAR;
		guint8 revchar = (guint8) revp[0];
		guint8 patch;
		guint32 release;
		guint32 date = release_date;
		guint32 build;
		gboolean ok;

#ifdef GTA_PATCHLEVEL
		patch = GTA_PATCHLEVEL;
#else
		patch = 0;
#endif

		poke_be32(&release, date);
		poke_be32(&build, main_get_build());

		ok =
			ggep_stream_begin(&gs, GGEP_NAME(GTKGV1), 0) &&
			ggep_stream_write(&gs, &major, 1) &&
			ggep_stream_write(&gs, &minor, 1) &&
			ggep_stream_write(&gs, &patch, 1) &&
			ggep_stream_write(&gs, &revchar, 1) &&
			ggep_stream_write(&gs, &release, 4) &&
			ggep_stream_write(&gs, &build, 4) &&
			ggep_stream_end(&gs);

		if (!ok)
			g_warning("could not write GGEP \"GTKGV1\" extension in query hit");
	}

	{
		const struct array *token = found_token();
		
		if (
			token->data &&
			!ggep_stream_pack(&gs, GGEP_NAME(SO), token->data, token->size, 0)
		)
			g_warning("could not add GGEP \"SO\" extension to query hit");
	}

	/*
	 * Look whether we'll need a "PUSH" GGEP extension to give out
	 * our current push proxies.  Prepare payload in `proxies'.
	 */

	if (is_firewalled) {
		GSList *nodes = node_push_proxies();

		if (nodes != NULL) {
			GSList *l;
			gint count;
			gchar proxy[6];
			gboolean ok;

			ok = ggep_stream_begin(&gs, GGEP_NAME(PUSH), 0);

			for (
				l = nodes, count = 0;
				ok && l && count < QHIT_MAX_PROXIES;
				l = g_slist_next(l), count++
			) {
				struct gnutella_node *n = l->data;

				if (NET_TYPE_IPV4 == host_addr_net(n->proxy_addr)) {
					poke_be32(&proxy[0], host_addr_ipv4(n->proxy_addr));
					poke_le16(&proxy[4], n->proxy_port);
					ok = ggep_stream_write(&gs, proxy, sizeof proxy);
				}
			}

			ok = ok && ggep_stream_end(&gs);

			if (!ok)
				g_warning("could not write GGEP \"PUSH\" extension "
					"in query hit");
		}
	}

	/*
	 * Look whether we can include an HNAME extension advertising the
	 * server's hostname.
	 */

	if (!is_firewalled && give_server_hostname && '\0' != server_hostname[0]) {
		gboolean ok;

		ok = ggep_stream_pack(&gs, GGEP_NAME(HNAME),
				server_hostname, strlen(server_hostname), 0);

		if (!ok)
			g_warning("could not write GGEP \"HNAME\" extension "
				"in query hit");
	}

	{
		const host_addr_t addr = listen_addr6();

		if (NET_TYPE_IPV6 == host_addr_net(addr)) {
			const guint8 *ipv6 = host_addr_ipv6(&addr);

			if (!ggep_stream_pack(&gs, GGEP_GTKG_NAME(IPV6), ipv6, 16, 0))
				g_warning("could not write GGEP \"GTKG.IPV6\" extension "
						"into query hit");
		}
	}

#ifdef HAS_GNUTLS
	if (!ggep_stream_pack(&gs, GGEP_GTKG_NAME(TLS), NULL, 0, 0))
		g_warning("could not write GGEP \"GTKG.TLS\" extension into query hit");
#endif /* HAS_GNUTLS */


	/*
	 * Advertise the Browse Host extension in the results if the feature is
	 * enabled.
     */

	if (browse_host_enabled) {
		if (!ggep_stream_pack(&gs, GGEP_NAME(BH), NULL, 0, 0))
			g_warning("could not write GGEP \"BH\" extension into query hit");
	}

	ggep_len = ggep_stream_close(&gs);
	found_close(ggep_len);

	if (ggep_len > 0)
		trailer_start[6] |= 0x20;		/* Has GGEP extensions in trailer */

	/*
	 * Store the GUID in the last 16 bytes of the query hit.
	 */

	if (!found_write(servent_guid, 16))
		goto failure;

	found_set_header();
	found_process();
	return;

failure:

	g_warning("Created query hit was too big, discarding");
	found_clear();
}

/**
 * Add file to current query hit.
 *
 * @returns TRUE if we inserted the record, FALSE if we refused it due to
 * lack of space.
 */
static gboolean
add_file(const struct shared_file *sf)
{
	gboolean sha1_available;
	gnet_host_t hvec[QHIT_MAX_ALT];
	gint hcnt = 0;
	guint32 fs32, fs32_le, idx_le;
	gint ggep_len;
	gboolean ok;
	ggep_stream_t gs;
	size_t left, needed;
	gpointer start;

	/* Cannot match partially downloaded files */
	g_assert(!shared_file_is_partial(sf));

	needed = 8 + 2 + shared_file_name_nfc_len(sf);	/* size of hit entry */

	sha1_available = SHARE_F_HAS_DIGEST ==
		(shared_file_flags(sf) & (SHARE_F_HAS_DIGEST | SHARE_F_RECOMPUTING));

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
		needed += 9 + SHA1_BASE32_SIZE;
		hcnt = dmesh_fill_alternate(shared_file_sha1(sf), hvec, QHIT_MAX_ALT);
		needed += hcnt * 6 + 6;
	}

	/*
	 * Refuse entry if we don't have enough room.	-- RAM, 22/01/2002
	 */

	if (
		found_size() + needed + QHIT_MIN_TRAILER_LEN
			> search_answers_forward_size
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

	poke_le32(&idx_le, shared_file_index(sf));
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
	 * From now on, we emit GGEP extensions, if we emit at all.
	 */

	left = found_left();
	start = found_open();
	ggep_stream_init(&gs, start, left);

	/*
	 * Emit the SHA1 as GGEP "H" if they said they understand it.
	 */

	if (sha1_available) {
		/* Modern way: GGEP "H" for binary URN */
		guint8 type = GGEP_H_SHA1;

		ok =
			ggep_stream_begin(&gs, GGEP_NAME(H), GGEP_W_COBS) &&
			ggep_stream_write(&gs, &type, 1) &&
			ggep_stream_write(&gs, shared_file_sha1(sf), SHA1_RAW_SIZE) &&
			ggep_stream_end(&gs);

		if (!ok)
			g_warning("could not write GGEP \"H\" extension in query hit");
	}

	/*
	 * If the 32-bit size is the magic ~0 escape value, we need to emit
	 * the real size in the "LF" extension.
	 */

	if (fs32 == ~0U) {
		gchar buf[sizeof(guint64)];
		gint len;

		len = ggept_lf_encode(shared_file_size(sf), buf);

		g_assert(len > 0 && len <= (gint) sizeof buf);

		ok = ggep_stream_pack(&gs, GGEP_NAME(LF), buf, len, GGEP_W_COBS);
		if (!ok)
			g_warning("could not write GGEP \"LF\" extension in query hit");
	}

	/*
	 * If we have known alternate locations, include a few of them for
	 * this file in the GGEP "ALT" extension.
	 */

	if (hcnt > 0) {
		gint i;

		g_assert(hcnt <= QHIT_MAX_ALT);

		ok = ggep_stream_begin(&gs, GGEP_NAME(ALT), GGEP_W_COBS);

		for (i = 0; ok && i < hcnt; i++) {
			g_assert(start == gs.outbuf);
			if (NET_TYPE_IPV4 == gnet_host_get_net(&hvec[i])) {
				gchar alt[6];
			
				poke_be32(&alt[0],
					host_addr_ipv4(gnet_host_get_addr(&hvec[i])));
				poke_le16(&alt[4], gnet_host_get_port(&hvec[i]));
				ok = ggep_stream_write(&gs, &alt, sizeof alt);
			}
		}

		ok = ok && ggep_stream_end(&gs);

		if (!ok)
			g_warning("could not write GGEP \"ALT\" extension in query hit");
	}

	{
		const gchar *rp = shared_file_relative_path(sf);
		
		if (rp) {
			ok = ggep_stream_pack(&gs, GGEP_NAME(PATH), rp, strlen(rp), 0);
			if (!ok)
				g_warning("could not add GGEP \"PATH\" extension to query hit");
		}
	}

	{
		time_t mtime;	

		/* FIXME: Create time != modification time */
		mtime = shared_file_modification_time(sf);
		if ((time_t) -1 != mtime) {
			gchar buf[sizeof(guint64)];
			gint len;

			/*
			 * Suppress negative values (if time_t is signed) as this would
			 * be interpreted as a date far in this future.
			 */
			mtime = MAX(0, mtime);

			len = ggept_ct_encode(mtime, buf);
			g_assert(len >= 0 && len <= (gint) sizeof buf);

			ok = ggep_stream_pack(&gs, GGEP_NAME(CT), buf, len, GGEP_W_COBS);
			if (!ok)
				g_warning("could not write GGEP \"CT\" extension in query hit");
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
found_reset(size_t max_size, const gchar *muid,
	qhit_process_t process, gpointer udata, const struct array *token)
{
	g_assert(process != NULL);
	g_assert(max_size <= INT_MAX);
	found_init(max_size, muid, process, udata, token);
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
 */
void
qhit_send_results(struct gnutella_node *n, GSList *files, gint count,
	const gchar *muid)
{
	GSList *sl;
	gint sent = 0;

	/*
	 * We can't use n->header.muid as the query's MUID but must rely on the
	 * parameter we're given.  Indeed, we're delivering a local hit here,
	 * but the query can have been OOB-proxified already and therefore the
	 * n->header.muid data have been mangled (since that is what we're going
	 * to forward to other nodes).
	 */

	found_reset(QHIT_SIZE_THRESHOLD, muid, qhit_send_node, n, &zero_array);

	for (sl = files; sl; sl = g_slist_next(sl)) {
		shared_file_t *sf = sl->data;
		if (add_file(sf))
			sent++;
		shared_file_unref(&sf);
	}

	if (0 != found_file_count())	/* Still some unflushed results */
		flush_match();				/* Send last packet */

	g_slist_free(files);

	if (dbg > 3)
		g_message("sent %d/%d hits to %s\n", sent, count, node_addr(n));
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
 */
void
qhit_build_results(const GSList *files, gint count, size_t max_msgsize,
	qhit_process_t cb, gpointer udata, const gchar *muid,
	const struct array *token)
{
	const GSList *sl;
	gint sent;

	g_assert(cb != NULL);
	g_assert(token);

	found_reset(max_msgsize, muid, cb, udata, token);

	for (sl = files, sent = 0; sl && sent < count; sl = g_slist_next(sl)) {
		const shared_file_t *sf = sl->data;

		if (add_file(sf))
			sent++;
	}

	if (0 != found_file_count())	/* Still some unflushed results */
		flush_match();				/* Send last packet */

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
	release_date = date2time(GTA_RELEASE, tm_time());
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
