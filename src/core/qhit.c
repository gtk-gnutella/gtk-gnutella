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
 * @file
 *
 * Query hit packet management.
 */

#include "common.h"

RCSID("$Id$");

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

#include "lib/getdate.h"
#include "lib/endian.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

#define QHIT_SIZE_THRESHOLD	2016	/* Flush query hits larger than this */
#define QHIT_SIZE_OOB		645		/* Flush OOB query hits larger than this */
#define QHIT_MAX_RESULTS	255		/* Maximum amount of hits in a query hit */
#define QHIT_MAX_ALT		5		/* Send out 5 alt-locs per entry, at most */
#define QHIT_MAX_PROXIES	5		/* Send out 5 push-proxies at most */
#define QHIT_MAX_GGEP		512		/* Allocated room for trailing GGEP */

/*
 * Minimal trailer length is our code NAME, the open flags, and the GUID.
 */
#define QHIT_MIN_TRAILER_LEN	(4+3+16)	/* NAME + open flags + GUID */

/*
 * Buffer where query hit packet is built.
 *
 * There is only one such packet, never freed.  At the beginning, one founds
 * the gnutella header, followed by the query hit header: initial offsetting
 * set by FOUND_RESET().
 *
 * The bufffer is logically (and possibly physically) extended via FOUND_GROW()
 * FOUND_BUF and FOUND_SIZE are used within the building code to access the
 * beginning of the query hit packet and the logical size of the packet.
 *
 *		--RAM, 25/09/2001
 */

static struct {
	guchar *d;					/* data */
	guint32 l;					/* data length */
	guint32 s;					/* size used by current search hit */
	guint files;				/* amount of file entries */
	gint max_size;				/* max query hit size */
	gboolean use_ggep_h;		/* whether to use GGEP "H" to send SHA1 */
	gchar *muid;				/* the MUID to put in all query hits */
	qhit_process_t process;		/* processor once query hit is built */
	gpointer udata;				/* processor argument */
} found_data;

#define FOUND_CHUNK		1024	/* Minimal growing memory amount unit */

#define FOUND_ENSURE(left) do {						\
	gint missing;									\
	missing = (left) - found_data.l;				\
	if (missing > 0) {								\
		missing = MAX(missing, FOUND_CHUNK);		\
		found_data.l += missing;					\
		found_data.d = (guchar *) g_realloc(found_data.d,	\
			found_data.l * sizeof(guchar));			\
	}												\
} while (0)

#define FOUND_GROW(len) do {						\
	found_data.s += (len);							\
	FOUND_ENSURE(found_data.s);						\
} while (0)

#define FOUND_RESET() do {							\
	found_data.s = sizeof(struct gnutella_header) +	\
		sizeof(struct gnutella_search_results_out);	\
	found_data.files = 0;							\
} while (0)

#define FOUND_INIT(m,xuid,ggep_h,proc,ud) do {		\
	found_data.max_size = (m);						\
	found_data.muid = (xuid);						\
	found_data.use_ggep_h = (ggep_h);				\
	found_data.process = (proc);					\
	found_data.udata = (ud);						\
} while (0)

#define FOUND_BUF		found_data.d
#define FOUND_SIZE		found_data.s
#define FOUND_FILES		found_data.files
#define FOUND_MAX_SIZE	found_data.max_size
#define FOUND_MUID		found_data.muid
#define FOUND_GGEP_H	found_data.use_ggep_h
#define FOUND_PROCESS	found_data.process
#define FOUND_UDATA		found_data.udata

#define FOUND_LEFT(x)	(found_data.l - (x))

static time_t release_date;

/**
 * Processor for query hits sent inbound.
 */
static void
qhit_send_node(gpointer data, gint len, gpointer udata)
{
	gnutella_node_t *n = (gnutella_node_t *) udata;
	struct gnutella_header *packet_head = (struct gnutella_header *) data;

	if (dbg > 3)
		printf("flushing query hit (%d entr%s, %d bytes sofar) to %s\n",
			FOUND_FILES, FOUND_FILES == 1 ? "y" : "ies", FOUND_SIZE,
			node_ip(n));

	/*
	 * We limit the TTL to the minimal possible value, then add a margin
	 * of 5 to account for re-routing abilities some day.  We then trim
	 * at our configured hard TTL limit.  Replies are precious packets,
	 * it would be a pity if they did not make it back to their source.
	 *
	 *			 --RAM, 02/02/2001
	 */

	if (n->header.hops == 0) {
		g_warning
			("search_request(): hops=0, bug in route_message()?\n");
		n->header.hops++;	/* Can't send message with TTL=0 */
	}

	packet_head->ttl = MIN((guint) n->header.hops + 5, hard_ttl_limit);

	gmsg_sendto_one(n, data, len);
}

/**
 * Flush pending search request to the network.
 */
static void
flush_match(void)
{
	gchar trailer[10];
	guint32 pos, pl;
	struct gnutella_header *packet_head;
	struct gnutella_search_results_out *search_head;
	gint ggep_len = 0;			/* Size of the GGEP trailer */
	guint32 connect_speed;		/* Connection speed, in kbits/s */
	ggep_stream_t gs;
	gchar *trailer_start;

	/*
	 * Build Gtk-gnutella trailer.
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

	pos = FOUND_SIZE;
	FOUND_GROW(7);
	memcpy(&FOUND_BUF[pos], trailer, 7);	/* Store the open trailer */
	trailer_start = &FOUND_BUF[pos];
	pos += 7;

	/*
	 * Ensure we can stuff at most QHIT_MAX_GGEP bytes of GGEP trailer.
	 */

	if (FOUND_LEFT(pos) < QHIT_MAX_GGEP)
		FOUND_ENSURE(QHIT_MAX_GGEP - FOUND_LEFT(pos));

	ggep_stream_init(&gs, &FOUND_BUF[pos], QHIT_MAX_GGEP);

	/*
	 * Build the "GTKGV1" GGEP extension.
	 */

	{
		guint8 major = GTA_VERSION;
		guint8 minor = GTA_SUBVERSION;
		gchar *revp = GTA_REVCHAR;
		guint8 revchar = (guint8) revp[0];
		guint8 patch;
		guint32 release;
		guint32 date = release_date;
		guint32 start;
		gboolean ok;

#ifdef GTA_PATCHLEVEL
		patch = GTA_PATCHLEVEL;
#else
		patch = 0;
#endif

		WRITE_GUINT32_BE(date, &release);
		WRITE_GUINT32_BE(start_stamp, &start);

		ok =
			ggep_stream_begin(&gs, "GTKGV1", 0) &&
			ggep_stream_write(&gs, &major, 1) &&
			ggep_stream_write(&gs, &minor, 1) &&
			ggep_stream_write(&gs, &patch, 1) &&
			ggep_stream_write(&gs, &revchar, 1) &&
			ggep_stream_write(&gs, &release, 4) &&
			ggep_stream_write(&gs, &start, 4) &&
			ggep_stream_end(&gs);

		if (!ok)
			g_warning("could not write GGEP \"GTKGV1\" extension in query hit");
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

			ok = ggep_stream_begin(&gs, "PUSH", 0);

			for (
				l = nodes, count = 0;
				ok && l && count < QHIT_MAX_PROXIES;
				l = g_slist_next(l), count++
			) {
				struct gnutella_node *n = (struct gnutella_node *) l->data;
				
				WRITE_GUINT32_BE(n->proxy_ip, &proxy[0]);
				WRITE_GUINT16_LE(n->proxy_port, &proxy[4]);
				ok = ggep_stream_write(&gs, proxy, sizeof(proxy));
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

	if (!is_firewalled && give_server_hostname && 0 != *server_hostname) {
		gboolean ok;

		ok = ggep_stream_pack(&gs, "HNAME",
				(gchar *) server_hostname, strlen(server_hostname), 0);

		if (!ok)
			g_warning("could not write GGEP \"HNAME\" extension "
				"in query hit");
	}

	ggep_len = ggep_stream_close(&gs);

	if (ggep_len > 0) {
		trailer_start[6] |= 0x20;		/* Has GGEP extensions in trailer */
		FOUND_GROW(ggep_len);
	}

	/*
	 * Store the GUID in the last 16 bytes of the query hit.
	 */

	pos = FOUND_SIZE;
	FOUND_GROW(16);
	memcpy(&FOUND_BUF[pos], guid, 16);	/* Store the GUID */

	/* Payload size including the search results header, actual results */
	pl = FOUND_SIZE - sizeof(struct gnutella_header);

	packet_head = (struct gnutella_header *) FOUND_BUF;
	packet_head->ttl = 1;		/* Overriden later if sending inbound */
	packet_head->hops = 0;
	memcpy(&packet_head->muid, FOUND_MUID, 16);

	packet_head->function = GTA_MSG_SEARCH_RESULTS;
	WRITE_GUINT32_LE(pl, packet_head->size);

	search_head = (struct gnutella_search_results_out *)
		&FOUND_BUF[sizeof(struct gnutella_header)];

	search_head->num_recs = FOUND_FILES;	/* One byte, little endian! */

	/*
	 * Compute connection speed dynamically if requested.
	 */

	connect_speed = connection_speed;
	if (compute_connection_speed) {
		connect_speed = max_uploads == 0 ?
			0 : (MAX(bsched_avg_bps(bws.out), bsched_bwps(bws.out)) * 8 / 1024);
		if (max_uploads > 0 && connect_speed == 0)
			connect_speed = 32;		/* No b/w limit set and no traffic yet */
	}
	connect_speed /= MAX(1, max_uploads);	/* Upload speed expected per slot */

	WRITE_GUINT16_LE(listen_port, search_head->host_port);
	WRITE_GUINT32_BE(listen_ip(), search_head->host_ip);
	WRITE_GUINT32_LE(connect_speed, search_head->host_speed);

	FOUND_PROCESS(FOUND_BUF, FOUND_SIZE, FOUND_UDATA);
}

/**
 * Add file to current query hit.
 *
 * Returns TRUE if we inserted the record, FALSE if we refused it due to
 * lack of space.
 */
static gboolean
add_file(struct shared_file *sf)
{
	guint32 pos = FOUND_SIZE;
	guint32 needed = 8 + 2 + sf->file_name_len;		/* size of hit entry */
	gboolean sha1_available;
	gnet_host_t hvec[QHIT_MAX_ALT];
	gint hcnt = 0;
	guint32 fs32;
	gint ggep_len;
	gboolean ok;
	ggep_stream_t gs;

	g_assert(sf->fi == NULL);	/* Cannot match partially downloaded files */

	sha1_available = SHARE_F_HAS_DIGEST ==
		(sf->flags & (SHARE_F_HAS_DIGEST | SHARE_F_RECOMPUTING));
	
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
		hcnt = dmesh_fill_alternate(sf->sha1_digest, hvec, QHIT_MAX_ALT);
		needed += hcnt * 6 + 6;
	}

	/*
	 * Refuse entry if we don't have enough room.	-- RAM, 22/01/2002
	 */

	if (pos + needed + QHIT_MIN_TRAILER_LEN > search_answers_forward_size)
		return FALSE;

	/*
	 * Grow buffer by the size of the search results header 8 bytes,
	 * plus the string length - NULL, plus two NULL's
	 */

	FOUND_GROW(needed);

	/*
	 * If size is greater than 2^31-1, we store ~0 as the file size and will
	 * use the "LF" GGEP extension to hold the real size.
	 */

	fs32 = sf->file_size > ((1U << 31) - 1) ? ~0U : sf->file_size;
	WRITE_GUINT32_LE(sf->file_index, &FOUND_BUF[pos]); pos += 4;
	WRITE_GUINT32_LE(fs32, &FOUND_BUF[pos]); pos += 4;

	memcpy(&FOUND_BUF[pos], sf->file_name, sf->file_name_len);
	pos += sf->file_name_len;

	/* Position equals the next byte to be writen to */

	FOUND_BUF[pos++] = '\0';

	/*
	 * We're now between the two NULs at the end of the hit entry.
	 */

	/*
	 * Emit the SHA1 as a plain ASCII URN if they don't grok "H".
	 */

	if (sha1_available && !FOUND_GGEP_H) {
		/* Good old way: ASCII URN */
		gchar *b32 = sha1_base32(sf->sha1_digest);
		memcpy(&FOUND_BUF[pos], "urn:sha1:", 9);
		pos += 9;
		memcpy(&FOUND_BUF[pos], b32, SHA1_BASE32_SIZE);
		pos += SHA1_BASE32_SIZE;
	}

	/*
	 * From now on, we emit GGEP extensions, if we emit at all.
	 */

	ggep_stream_init(&gs, &FOUND_BUF[pos], FOUND_LEFT(pos));

	/*
	 * Emit the SHA1 as GGEP "H" if they said they understand it.
	 */

	if (sha1_available && FOUND_GGEP_H) {
		/* Modern way: GGEP "H" for binary URN */
		guint8 type = GGEP_H_SHA1;

		ok =
			ggep_stream_begin(&gs, "H", GGEP_W_COBS) &&
			ggep_stream_write(&gs, &type, 1) &&
			ggep_stream_write(&gs, sf->sha1_digest, SHA1_RAW_SIZE) &&
			ggep_stream_end(&gs);

		if (!ok)
			g_warning("could not write GGEP \"H\" extension in query hit");
	}

	/*
	 * If the 32-bit size is the magic ~0 escape value, we need to emit
	 * the real size in the "LF" extension.
	 */

	if (fs32 == ~0U) {
		guint8 buf[sizeof(guint64)];
		gint len;

		len = ggep_lf_encode(sf->file_size, buf); 

		g_assert(len > 0 && len <= (gint) sizeof buf);

		ok = ggep_stream_pack(&gs, "LF", buf, len, GGEP_W_COBS);
		
		if (!ok)
			g_warning("could not write GGEP \"LF\" extension in query hit");
	}

	/*
	 * If we have known alternate locations, include a few of them for
	 * this file in the GGEP "ALT" extension.
	 */

	if (hcnt > 0) {
		gchar alt[6];
		gint i;

		g_assert(hcnt <= QHIT_MAX_ALT);

		ok = ggep_stream_begin(&gs, "ALT", GGEP_W_COBS);

		for (i = 0; ok && i < hcnt; i++) {
			WRITE_GUINT32_BE(hvec[i].ip, &alt[0]);
			WRITE_GUINT16_LE(hvec[i].port, &alt[4]);
			ok = ggep_stream_write(&gs, alt, sizeof(alt));
		}

		ok = ok && ggep_stream_end(&gs);

		if (!ok)
			g_warning("could not write GGEP \"ALT\" extension in query hit");
	}

	ggep_len = ggep_stream_close(&gs);

	pos += ggep_len;

	FOUND_BUF[pos++] = '\0';
	FOUND_FILES++;

	/*
	 * Because we don't know exactly the size of the GGEP extension
	 * (could be COBS-encoded or not), we need to adjust the real
	 * extension size now that the entry is fully written.
	 */

	FOUND_SIZE = pos;

	/*
	 * If we have reached our size limit for query hits, flush what
	 * we have so far.
	 */

	if (FOUND_SIZE >= FOUND_MAX_SIZE || FOUND_FILES >= QHIT_MAX_RESULTS) {
		flush_match();
		FOUND_RESET();
	}

	return TRUE;		/* Hit entry accepted */
}

/**
 * Reset the QueryHit, that is, the "data found" pointer is at the beginning of
 * the data found section in the query hit packet.
 *
 * @param max_size the maximum size in bytes of individual query hits
 *
 * @param use_ggep_h whether GGEP "H" can be used to send the SHA1 of files
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
found_reset(
	gint max_size, gchar *muid,
	gboolean use_ggep_h, qhit_process_t process, gpointer udata)
{
	FOUND_INIT(max_size, muid, use_ggep_h, process, udata);
	FOUND_RESET();
}

/**
 * Send as many small query hit packets as necessary to hold the `count'
 * results held in the `files' list.
 *
 * @param n				the node where we should send results to
 * @param files			the list of shared_file_t entries that make up results
 * @param count			the amount of results
 * @param use_ggep_h	whether GGEP "H" can be used to send the SHA1 of files
 */
void
qhit_send_results(
	struct gnutella_node *n, GSList *files, gint count, gboolean use_ggep_h)
{
	GSList *sl;
	gint sent = 0;

	found_reset(QHIT_SIZE_THRESHOLD, n->header.muid,
		use_ggep_h, qhit_send_node, n);

	for (sl = files; sl; sl = g_slist_next(sl)) {
		shared_file_t *sf = (shared_file_t *) sl->data;
		if (add_file(sf))
			sent++;
		shared_file_unref(sf);
	}

	if (FOUND_FILES)			/* Still some unflushed results */
		flush_match();			/* Send last packet */

	g_slist_free(files);

	if (dbg > 3)
		printf("sent %d/%d hits to %s\n", sent, count, node_ip(n));
}

/**
 * Build query hit results for later out-of-band delivery.
 *
 * @param cb			the processor callback to invoke on each built hit
 * @param udata			argument to pass to callback (OOB recording strcuture)
 * @param muid			the MUID to use on each generated hit
 * @param files			the list of shared_file_t entries that make up results
 * @param count			the amount of results
 * @param use_ggep_h	whether GGEP "H" can be used to send the SHA1 of files
 */
void
qhit_build_results(
	qhit_process_t cb, gpointer udata,
	gchar *muid, GSList *files, gint count, gboolean use_ggep_h)
{
	GSList *sl;
	gint sent;

	found_reset(QHIT_SIZE_OOB, muid, use_ggep_h, cb, udata);

	for (sl = files, sent = 0; sl && sent < count; sl = g_slist_next(sl)) {
		shared_file_t *sf = (shared_file_t *) sl->data;

		if (add_file(sf))
			sent++;
	}

	if (FOUND_FILES)			/* Still some unflushed results */
		flush_match();			/* Send last packet */

	/*
	 * Nothing to free, since everything is the property of the OOB module.
	 */
}

/**
 * Initialization of the query hit generation.
 */
void
qhit_init(void)
{
	found_data.l = FOUND_CHUNK;		/* must be > size after found_reset */
	found_data.d = (guchar *) g_malloc(found_data.l * sizeof(guchar));

	release_date = date2time(GTA_RELEASE, time(NULL));
}

/**
 * Shutdown cleanup.
 */
void
qhit_close(void)
{
	G_FREE_NULL(found_data.d);
}

/* vi: set ts=4 sw=4 cindent: */
