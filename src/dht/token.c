/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup dht
 * @file
 *
 * DHT security tokens.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#include "token.h"
#include "knode.h"

#include "lib/sectoken.h"
#include "lib/override.h"		/* Must be the last header included */

#define T_KEYS				2			/* Amount of keys we manage */
#define T_FW_PORT			65535		/* Port used for firewalled nodes */
#define T_REFRESH_PERIOD	(181*60)	/* 3 hours + 1 minute */

static sectoken_gen_t *token_stg;		/**< DHT token generator */

/**
 * @return lifetime in seconds of the security tokens we generate.
 */
time_delta_t
token_lifetime(void)
{
	return T_REFRESH_PERIOD * T_KEYS;
}

/**
 * Create a 4-byte security token for remote Kademlia node.
 */
void
token_generate(sectoken_t *tok, const knode_t *kn)
{
	knode_check(kn);

	/*
	 * If node is firewalled and uses NAT, the UDP port used will likely be
	 * different each time.  Substitute a constant port in that case.
	 */

	sectoken_generate(token_stg, tok, kn->addr,
		(kn->flags & KNODE_F_FIREWALLED) ? T_FW_PORT : kn->port);
}

/*
 * Is specified token still valid for this Kademlia node?
 */
bool
token_is_valid(const sectoken_t *tok, const knode_t *kn)
{
	/*
 	 * The lifetime of security tokens is T_KEYS * T_REFRESH_PERIOD_MS
	 * and it must be greater than 1 hour since this is the period for
	 * Kademlia replication, hence bucket refreshes from closest neighbours
	 * or node lookups...
	 *
	 * LW nodes seem to cache the security token somehow because I've seen
	 * STORE from closest node failing to provide the proper token when the
	 * lifetime of the token was only of 20 minutes.  Be nice.
	 */

	STATIC_ASSERT(T_REFRESH_PERIOD * T_KEYS >= 3600);

	return sectoken_is_valid(token_stg, tok, kn->addr,
		(kn->flags & KNODE_F_FIREWALLED) ? T_FW_PORT : kn->port);
}

/**
 * Initialize the security tokens.
 */
void
token_init(void)
{
	g_assert(NULL == token_stg);

	token_stg = sectoken_gen_new(T_KEYS, T_REFRESH_PERIOD);
}

/**
 * Close the security tokens.
 */
void
token_close(void)
{
	sectoken_gen_free_null(&token_stg);
}

/* vi: set ts=4 sw=4 cindent: */
