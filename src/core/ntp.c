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
 * Detection of a local NTP server.
 */

#include "common.h"

RCSID("$Id$");

#include "ntp.h"
#include "sockets.h"

#include "if/core/hosts.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/override.h"		/* Must be the last header included */

#define OFFSET_1900		2208988800U		/* secs between 1900 and the Epoch */
#define NTP_FP_SCALE	4294967296.0	/* NTP fixed-point scaling base */

#define NTP_WAIT_MS		(5*1000)		/* Wait at most 5 secs for reply */
#define NTP_VERSION		3				/* Say we're version 3 */
#define NTP_CLIENT		3				/* Mode for unicast request */
#define NTP_SERVER		4				/* Mode for server reply */
#define NTP_AUTHSIZE	20				/* Size of NTP auth, when present */

#define NTP_MINSIZE		sizeof(struct ntp_msg)
#define NTP_MAXSIZE		(NTP_MINSIZE + NTP_AUTHSIZE)

static gpointer wait_ev = NULL;			/* Callout queue waiting event */

/*
 * An NTP message, as described in RFC2030 (trailing auth-data ignored).
 */
struct ntp_msg {
	guint8 flags;
	guint8 stratum;
	guint8 poll;
	guint8 precision;
	guchar root_delay[4];
	guchar root_dispersion[4];
	guchar reference_id[4];
	guchar reference_timestamp[8];
	guchar originate_timestamp[8];
	guchar receive_timestamp[8];
	guchar transmit_timestamp[8];
} __attribute__((__packed__));

/**
 * Fill 8-byte buffer with NTP's representation of a tm_t time.
 */
static void
ntp_tm_serialize(guchar dest[8], tm_t *t)
{
	guint32 b;

	b = (guint32) t->tv_sec + OFFSET_1900;
	WRITE_GUINT32_BE(b, &dest[0]);

	b = (guint32) (t->tv_usec * 1.0e-6 * NTP_FP_SCALE);
	WRITE_GUINT32_BE(b, &dest[4]);
}

/**
 * Construct a tm_t time from an NTP timestamp.
 */
static void
ntp_tm_deserialize(guchar src[8], tm_t *dest)
{
	guint32 b;

	READ_GUINT32_BE(&src[0], b);
	dest->tv_sec = b - OFFSET_1900;

	READ_GUINT32_BE(&src[4], b);
	dest->tv_usec = (gint) (b * 1.0e6 / NTP_FP_SCALE);
}

/**
 * Callout queue timeout when no reply is received within a reasonable
 * timeframe.
 */
static void
ntp_no_reply(cqueue_t *cq, gpointer uddata)
{
	if (dbg)
		printf("NTP no reply from localhost\n");

	gnet_prop_set_boolean_val(PROP_HOST_RUNS_NTP, FALSE);
}

/**
 * Send an NTP probe to local host using the loopback 127.0.0.1 address,
 * waiting for a reply within the next NTP_WAIT_MS ms.
 */
void
ntp_probe(void)
{
	tm_t now;
	struct ntp_msg m;
	gnet_host_t to;

	if (!enable_udp)
		return;

	memset(&m, 0, sizeof(m));
	m.flags = (NTP_VERSION) << 3 | NTP_CLIENT;
	tm_now(&now);
	ntp_tm_serialize(m.transmit_timestamp, &now);

	to.ip = gchar_to_ip("127.0.0.1");
	to.port = NTP_PORT;

	if (-1 == s_udp_listen->wio.sendto(&s_udp_listen->wio, &to, &m, sizeof(m)))
		return;

	/*
	 * Arm timer to see whether we get a reply in the next NTP_WAIT_MS.
	 */

	if (dbg)
		printf("NTP sent probe to localhost\n");

	if (wait_ev != NULL)
		cq_cancel(callout_queue, wait_ev);

	wait_ev = cq_insert(callout_queue, NTP_WAIT_MS, ntp_no_reply, NULL);
}

/**
 * Got a reply from an NTP daemon.
 */
void
ntp_got_reply(struct gnutella_socket *s)
{
	struct ntp_msg *m;
	guint8 version;
	guint8 mode;
	tm_t received;
	tm_t sent;
	tm_t replied;
	tm_t got;
	tm_t offset;
	double clock_offset;

	tm_now(&got);

	if (s->pos != NTP_MINSIZE && s->pos != NTP_MAXSIZE) {
		g_warning("got weird reply from NTP server (%d bytes)", s->pos);
		return;
	}

	m = (struct ntp_msg *) s->buffer;
	mode = m->flags & 0x7;
	version = (m->flags >> 3) & 0x7;

	if (mode != NTP_SERVER) {
		g_warning("got reply from NTP server with weird mode (%d)", mode);
		return;
	}

	if (dbg)
		printf("NTP got %s reply from NTP-%u server, stratum %u\n",
			s->pos == NTP_MINSIZE ? "regular" : "auth", version, m->stratum);

	/*
	 * Since we know NTP runs locally, disarm the timeout.
	 */

	if (wait_ev != NULL) {
		cq_cancel(callout_queue, wait_ev);
		wait_ev = NULL;
	}

	gnet_prop_set_boolean_val(PROP_HOST_RUNS_NTP, TRUE);

	/*
	 * Compute the initial clock offset.
	 * This is given by: ((received - sent) + (replied - got)) / 2
	 */

	ntp_tm_deserialize(m->originate_timestamp, &sent);
	ntp_tm_deserialize(m->receive_timestamp, &received);
	ntp_tm_deserialize(m->transmit_timestamp, &replied);

	offset = received;		/* Struct copy */
	tm_sub(&offset, &sent);
	tm_add(&offset, &replied);
	tm_sub(&offset, &got);

	clock_offset = tm2f(&offset) / 2;		/* Should be close to 0 */

	if (dbg > 1)
		printf("NTP local clock offset is %.6lf secs\n", clock_offset);

	gnet_prop_set_guint32_val(PROP_CLOCK_SKEW, (guint32) clock_offset);

	g_message("detected NTP-%u, stratum %u, offset %.6lf secs",
		version, m->stratum, clock_offset);
}

/**
 * Initialize the NTP monitoring.
 */
void
ntp_init(void)
{
	ntp_probe();
}

/**
 * Shutdown the NTP monitoring.
 */
void
ntp_close(void)
{
	if (wait_ev != NULL)
		cq_cancel(callout_queue, wait_ev);
}

/* vi: set ts=4: */

