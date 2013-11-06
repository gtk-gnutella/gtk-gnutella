/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Sychronization dam.
 *
 * A dam is a thread synchronization primitive allowing parallel processing
 * to halt until the dam owner decides to release the waiting parties.
 *
 * Contrary to a barrier, the dam is not pre-configured with an amount of
 * parties that need to join.  Rather, it is a halting point for all reaching
 * parties until the owner determines that processing can continue.
 *
 * The owner of the dam is given a random key, and only that key can be used
 * to successfully open the dam to release the waiting threads.  This ensures
 * nobody but the creator of the dam can accidentally release it.
 *
 * To atomically make the dam a non-blocking points (before freeing it), the
 * owner can disable it: this will also release all the waiting parties.
 * Anyone still holding a reference to that dam will no longer block when
 * calling dam_wait() and friends.
 *
 * Here is our API:
 *
 *		dam_new()				-- allocates a new dam
 *		dam_free_nul()			-- free dynamically allocated dam
 *		dam_wait()				-- wait for the dam to be released
 *		dam_timed_wait()		-- wait on the dam until timeout expires
 *		dam_wait_until()		-- wait on the dam until given absolute time
 *		dam_release()			-- release all threads waiting on the dam
 *		dam_disable()			-- disable dam and release all threads waiting
 *		dam_refcnt_inc()		-- take an extra reference on the dam
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _dam_h_
#define _dam_h_

struct dam;
typedef struct dam dam_t;

struct tmval;

/*
 * Public interface.
 */

dam_t *dam_new(uint *key);
dam_t *dam_new_full(uint *key, bool emulated);
void dam_free_null(dam_t **d_ptr);
void dam_wait(dam_t *d);
bool dam_timed_wait(dam_t *d, const struct tmval *timeout);
bool dam_wait_until(dam_t *d, const struct tmval *abstime);
void dam_release(dam_t *d, uint key);
void dam_disable(dam_t *d, uint key);
bool dam_is_disabled(const dam_t *d);
dam_t *dam_refcnt_inc(dam_t *d);

#endif /* _dam_h_ */

/* vi: set ts=4 sw=4 cindent: */
