/*
 * $Id$
 *
 * Copyright (c) 2003, Jeroen Asselman
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
 * Tigertree hash verification.
 *
 * This is not ready yet at all, do not try to use it yet. It is included
 * for compilation reasons only.
 *
 * @author Jeroen Asselman
 * @date 2003
 */

#include "common.h"

RCSID("$Id$")

#include "downloads.h"
#include "file_object.h"
#include "guid.h"
#include "huge.h"
#include "sockets.h"
#include "tth_cache.h"
#include "verify_tth.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/bg.h"
#include "lib/hashlist.h"
#include "lib/file.h"
#include "lib/tigertree.h"
#include "lib/tiger.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last inclusion */

static struct {
	struct verify	*verify;
	TTH_CONTEXT		*context;
	struct tth		digest;
} verify_tth;

static const char *
verify_tth_name(void)
{
	return "TTH";
}

static void
verify_tth_reset(filesize_t size)
{
	tt_init(verify_tth.context, size);
}

static int
verify_tth_update(const void *data, size_t size)
{
	tt_update(verify_tth.context, data, size);
	return 0;
}

static int
verify_tth_final(void)
{
	tt_digest(verify_tth.context, &verify_tth.digest);
	return 0;
}

static const struct verify_hash verify_hash_tth = {
	verify_tth_name,
	verify_tth_reset,
	verify_tth_update,
	verify_tth_final,
};

void
verify_tth_append(const char *pathname, filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	verify_append(verify_tth.verify,
		pathname, offset, amount, callback, user_data);
}

void
verify_tth_prepend(const char *pathname, filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	verify_prepend(verify_tth.verify,
		pathname, offset, amount, callback, user_data);
}

const struct tth *
verify_tth_digest(const struct verify *ctx)
{
	g_return_val_if_fail(verify_status(ctx) == VERIFY_DONE, NULL);
	return &verify_tth.digest;
}

const struct tth *
verify_tth_leaves(const struct verify *ctx)
{
	g_return_val_if_fail(verify_status(ctx) == VERIFY_DONE, NULL);
	return tt_leaves(verify_tth.context);
}

size_t
verify_tth_leave_count(const struct verify *ctx)
{
	g_return_val_if_fail(verify_status(ctx) == VERIFY_DONE, 0);
	return tt_leave_count(verify_tth.context);
}

void
verify_tth_init(void)
{
	static int initialized;

	if (!initialized) {
		initialized = TRUE;

		verify_tth.context = walloc(tt_size());
		verify_tth.verify = verify_new(&verify_hash_tth);
	}
}

/**
 * Stops the background task for tigertree verification.
 */
void
verify_tth_close(void)
{
	verify_free(&verify_tth.verify);
}

static gboolean 
request_tigertree_callback(const struct verify *ctx, enum verify_status status,
	void *user_data)
{
	struct shared_file *sf = user_data;

	shared_file_check(sf);
	switch (status) {
	case VERIFY_START:
		gnet_prop_set_boolean_val(PROP_TTH_REBUILDING, TRUE);
		return TRUE;
	case VERIFY_PROGRESS:
		return TRUE;
	case VERIFY_DONE:
		{
			const struct tth *tth = verify_tth_digest(ctx);
			
			huge_update_hashes(sf, shared_file_sha1(sf), tth);
			tth_cache_insert(tth, verify_tth_leaves(ctx),
				verify_tth_leave_count(ctx));
		}
		/* FALL THROUGH */
	case VERIFY_ERROR:
	case VERIFY_SHUTDOWN:
		shared_file_unref(&sf);
		gnet_prop_set_boolean_val(PROP_TTH_REBUILDING, FALSE);
		return TRUE;
	case VERIFY_INVALID:
		break;
	}
	g_assert_not_reached();
	return FALSE;
}

void
request_tigertree(struct shared_file *sf, gboolean high_priority)
{
	const struct tth *tth;

	if (!experimental_tigertree_support)
		return;

	verify_tth_init();

	g_return_if_fail(sf);
	shared_file_check(sf);
	g_return_if_fail(!shared_file_is_partial(sf));

	tth = shared_file_tth(sf);
	if (tth) {
		size_t ret;
		
		ret = tth_cache_lookup(tth, shared_file_size(sf));
		if (ret > 0) {
			if (tigertree_debug > 1) {
				g_message("TTH %s is already cached", tth_base32(tth));
			}
		} else {
			huge_update_hashes(sf, shared_file_sha1(sf), NULL);
		}
	} else {

		if (high_priority) {
			verify_tth_prepend(shared_file_path(sf), 0, shared_file_size(sf),
				request_tigertree_callback, shared_file_ref(sf));
		} else {
			verify_tth_append(shared_file_path(sf), 0, shared_file_size(sf),
				request_tigertree_callback, shared_file_ref(sf));
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
