/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Memory usage statistics collection.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _memusage_h_
#define _memusage_h_

struct memusage;
typedef struct memusage memusage_t;

/*
 * Public interface.
 */

memusage_t *memusage_alloc(const char *name, size_t width);
void memusage_free_null(memusage_t **mu_ptr);
void memusage_add(memusage_t *mu, size_t size);
void memusage_add_one(memusage_t *mu);
void memusage_add_batch(memusage_t *mu, size_t count);
void memusage_remove(memusage_t *mu, size_t size);
void memusage_remove_one(memusage_t *mu);
void memusage_remove_multiple(memusage_t *mu, size_t n);
void memusage_set_stack_accounting(memusage_t *mu, bool on);

bool memusage_is_valid(const memusage_t * const mu) G_PURE;

struct logagent;

void memusage_frame_dump_log(const memusage_t *mu, struct logagent *la);
void memusage_summary_dump_log(const memusage_t *mu,
	struct logagent *la, unsigned opt);

#endif /* _memusage_h_ */

/* vi: set ts=4 sw=4 cindent: */
