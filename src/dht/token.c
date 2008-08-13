/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Security tokens.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "token.h"
#include "knode.h"

#include "lib/atoms.h"			/* For binary_hash() */
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/host_addr.h"
#include "lib/misc.h"
#include "lib/tea.h"
#include "lib/override.h"		/* Must be the last header included */

#define T_KEYS				2		/* Amount of keys we manage */
#define T_FW_PORT			65535	/* Port used for firewalled nodes */
#define T_REFRESH_PERIOD_MS	(60*60*1000)	/* 1 hour in ms */

static tea_key_t keys[T_KEYS];		/**< Rotating set of keys */
static cevent_t *rotate_ev;			/**< Rotate event */

/**
 * Create a 4-byte security token from host address and port.
 */
static void
generate(token_t *tok, host_addr_t addr, guint16 port)
{
	char block[8];
	char enc[8];
	char *p = block;

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		p = poke_be32(p, host_addr_ipv4(addr));
		break;
	case NET_TYPE_IPV6:
		{
			guint val;

			val = binary_hash(host_addr_ipv6(&addr), 16);
			p = poke_be32(p, val);
		}
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_error("unexpected address for security token generation: %s",
			host_addr_to_string(addr));
	}

	p = poke_be16(p, port);
	p = poke_be16(p, 0);		/* Filler */

	g_assert(p == &block[8]);

	STATIC_ASSERT(sizeof(tok->v) == sizeof(guint32));
	STATIC_ASSERT(sizeof(block) == sizeof(enc));

	tea_encrypt(&keys[0], enc, block, sizeof block);
	poke_be32(tok->v, tea_squeeze(enc, sizeof enc));
}

/**
 * Create a 4-byte security token for remote Kademlia node.
 */
void
token_generate(token_t *tok, const knode_t *kn)
{
	g_assert(KNODE_MAGIC == kn->magic);

	/*
	 * If node is firewalled and uses NAT, the UDP port used will likely be
	 * different each time.  Substitute a constant port in that case.
	 */

	generate(tok, kn->addr,
		(kn->flags & KNODE_F_FIREWALLED) ? T_FW_PORT : kn->port);
}

/*
 * Is specified token still valid for this Kademlia node?
 */
gboolean
token_is_valid(const token_t *tok, const knode_t *kn)
{
	size_t i;

	STATIC_ASSERT(sizeof(tok->v) == TOKEN_RAW_SIZE);

	/*
 	 * The lifetime of security tokens is T_KEYS * T_REFRESH_PERIOD_MS
	 * and it must be greater than 1 hour since this is the period for
	 * Kademlia republishing, hence bucket refreshes from closest neighbours
	 * or node lookups...
	 *
	 * LW nodes seem to cache the security token somehow because I've seen
	 * STORE from closest node failing to provide the proper token when the
	 * lifetime of the token was only of 20 minutes.  Be nice.
	 */

	STATIC_ASSERT(T_REFRESH_PERIOD_MS / 1000 * T_KEYS >= 3600);

	/*
	 * We can't decrypt, we just generate a new token with the set of
	 * keys and say the token is valid if it matches with the one we're
	 * generating.
	 *
	 * We try the most recent key first as it is the most likely to succeed.
	 */

	for (i = 0; i < G_N_ELEMENTS(keys); i++) {
		token_t gen;

		token_generate(&gen, kn);
		if (0 == memcmp(gen.v, tok->v, TOKEN_RAW_SIZE))
			return TRUE;
	}

	return FALSE;
}

/**
 * Token key rotating event.
 */
static void
token_rotate(cqueue_t *unused_cq, gpointer unused_obj)
{
	size_t i;

	(void) unused_cq;
	(void) unused_obj;

	rotate_ev = cq_insert(callout_queue, T_REFRESH_PERIOD_MS,
		token_rotate, NULL);

	for (i = 0; i < G_N_ELEMENTS(keys) - 1; i++)
		keys[i + 1] = keys[i];

	random_bytes(&keys[0], sizeof(keys[0]));	/* 0 is most recent key */
}

/**
 * Initialize the security tokens.
 */
void
token_init(void)
{
	size_t i;

	STATIC_ASSERT(G_N_ELEMENTS(keys) > 1);

	for (i = 0; i < G_N_ELEMENTS(keys); i++)
		random_bytes(&keys[i], sizeof(keys[i]));

	rotate_ev = cq_insert(callout_queue, T_REFRESH_PERIOD_MS,
		token_rotate, NULL);
}

/**
 * Close the security tokens.
 */
void
token_close(void)
{
	cq_cancel(callout_queue, &rotate_ev);
}

/* vi: set ts=4 sw=4 cindent: */
