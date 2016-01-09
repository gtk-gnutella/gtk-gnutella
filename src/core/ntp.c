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
 * Detection of a local NTP server.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "ntp.h"
#include "settings.h"
#include "urpc.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/tm.h"
#include "lib/override.h"				/* Must be the last header included */

#define OFFSET_1900		2208988800U		/**< secs between 1900 and the Epoch */
#define NTP_FP_SCALE	4294967296.0	/**< NTP fixed-point scaling base */

#define NTP_WAIT_MS		(5*1000)		/**< Wait at most 5 secs for reply */
#define NTP_VERSION		3				/**< Say we're version 3 */
#define NTP_CLIENT		3				/**< Mode for unicast request */
#define NTP_SERVER		4				/**< Mode for server reply */
#define NTP_AUTHSIZE	20				/**< Size of NTP auth, when present */

#define NTP_MINSIZE		sizeof(struct ntp_msg)
#define NTP_MAXSIZE		(NTP_MINSIZE + NTP_AUTHSIZE)

/**
 * An NTP message, as described in RFC2030 (trailing auth-data ignored).
 */
struct ntp_msg {
	uint8 flags;
	uint8 stratum;
	uint8 poll;
	uint8 precision;
	uchar root_delay[4];
	uchar root_dispersion[4];
	uchar reference_id[4];
	uchar reference_timestamp[8];
	uchar originate_timestamp[8];
	uchar receive_timestamp[8];
	uchar transmit_timestamp[8];
};

static bool ntp_localhost_replied;

/**
 * Fill 8-byte buffer with NTP's representation of a tm_t time.
 */
static void
ntp_tm_serialize(uchar dest[8], tm_t *t)
{
	poke_be32(&dest[0], t->tv_sec + OFFSET_1900);
	poke_be32(&dest[4], t->tv_usec * 1.0e-6 * NTP_FP_SCALE);
}

/**
 * Construct a tm_t time from an NTP timestamp.
 */
static void
ntp_tm_deserialize(const uchar src[8], tm_t *dest)
{
	dest->tv_sec = peek_be32(&src[0]) - OFFSET_1900;
	dest->tv_usec = (uint32) (peek_be32(&src[4]) * 1.0e6 / NTP_FP_SCALE);
}

/**
 * Callout queue timeout when no reply is received within a reasonable
 * timeframe.
 */
static void
ntp_no_reply(void)
{
	if (ntp_localhost_replied)
		return;

	if (GNET_PROPERTY(tsync_debug))
		g_debug("NTP no reply from localhost");

	/*
	 * Don't set PROP_HOST_RUNS_NTP to FALSE.  If they force it to TRUE,
	 * because they run "ntpdate" once in a while, we'll ignore the
	 * computed clock skew but we won't advertise to others that we're
	 * running NTP if we haven't detected it.
	 *		--RAM, 2004-10-27.
	 */

	gnet_prop_set_boolean_val(PROP_NTP_DETECTED, FALSE);
}

/**
 * Got a reply from an NTP daemon.
 */
static void
ntp_got_reply(host_addr_t addr, const void *payload, size_t len)
{
	const struct ntp_msg *m;
	uint8 version;
	uint8 mode;
	tm_t received;
	tm_t sent;
	tm_t replied;
	tm_t got;
	tm_t offset;
	double clock_offset;

	tm_now_exact(&got);

	g_info("NTP detected at %s", host_addr_to_string(addr));

	if (len != NTP_MINSIZE && len != NTP_MAXSIZE) {
		g_warning("got weird reply from NTP server (%zu bytes)", len);
		return;
	}

	m = payload;
	mode = m->flags & 0x7;
	version = (m->flags >> 3) & 0x7;

	if (mode != NTP_SERVER) {
		g_warning("got reply from NTP server with weird mode (%d)", mode);
		return;
	}

	if (GNET_PROPERTY(tsync_debug))
		g_debug("NTP got %s reply from NTP-%u server, stratum %u",
			NTP_MINSIZE == len ? "regular" : "auth", version, m->stratum);

	/*
	 * We know NTP runs locally.
	 */

	gnet_prop_set_boolean_val(PROP_HOST_RUNS_NTP, TRUE);
	gnet_prop_set_boolean_val(PROP_NTP_DETECTED, TRUE);

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

	if (GNET_PROPERTY(tsync_debug) > 1)
		g_debug("NTP local clock offset is %g secs",
			(double) clock_offset);

	gnet_prop_set_guint32_val(PROP_CLOCK_SKEW, (uint32) clock_offset);

	g_info("detected NTP-%u, stratum %u, offset %g secs",
		version, m->stratum, (double) clock_offset);
}

/**
 * Reception / timeout callback for NTP probes.
 */
static void
ntp_received(enum urpc_ret type, host_addr_t addr, uint16 unused_port,
	const void *payload, size_t len, void *unused_arg)
{
	(void) unused_port;
	(void) unused_arg;

	if (URPC_ABORT == type)
		return;

	if (URPC_TIMEOUT == type) {
		ntp_no_reply();
		return;
	}

	ntp_localhost_replied = TRUE;
	ntp_got_reply(addr, payload, len);
}

static bool
ntp_send_probe(const host_addr_t addr)
{
	static const struct ntp_msg zero_m;
	struct ntp_msg m;
	tm_t now;

	m = zero_m;
	m.flags = (NTP_VERSION << 3) | NTP_CLIENT;
	tm_now_exact(&now);
	ntp_tm_serialize(m.transmit_timestamp, &now);

	return 0 == urpc_send("NTP", addr, NTP_PORT, &m, sizeof m, NTP_WAIT_MS,
		ntp_received, NULL);
}

static bool G_COLD
ntp_send_probes(void)
{
	static const struct {
		const char *addr;
	} hosts[] = {
#if 0
		/* Skip this for now. We check replies only against 127.0.0.1 and ::1
		 * anyway and there is also the minor DNS issue below. */
		{ "localhost" },
#endif
		{ "::1"		  },
		{ "127.0.0.1" },
	};
	bool sent = FALSE;
	uint i;

	/* TODO:	The name_to_host_addr() could take a while which would
	 *			delay startup. Thus, use ADNS for this.
	 */

	for (i = 0; i < G_N_ELEMENTS(hosts); i++) {
		host_addr_t addr;

		addr = name_to_single_host_addr(hosts[i].addr, settings_dns_net());
		if (!is_host_addr(addr))
			continue;
		
		if (ntp_send_probe(addr)) {
			/* Send probes to all addresses because a successful sendto()
			 * does not guarantee anything. */
			sent = TRUE;
		} else if (GNET_PROPERTY(tsync_debug)) {
			g_debug("NTP ntp_probe(): sendto() failed for \"%s\" (\"%s\"): %m",
				hosts[i].addr,
				host_addr_to_string(addr));
		}
	}

	return sent;
}

/**
 * Send an NTP probe to the local host using the loopback addresses 127.0.0.1
 * and ::1, waiting for a reply within the next NTP_WAIT_MS ms.
 */
void
ntp_probe(void)
{
	if (!ntp_send_probes())
		return;

	if (GNET_PROPERTY(tsync_debug))
		g_debug("NTP sent probe to localhost");
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
}

/* vi: set ts=4 sw=4 cindent: */

