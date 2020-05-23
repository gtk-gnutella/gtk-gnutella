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
 * @ingroup lib
 * @file
 *
 * Practical Algorithm To Retrieve Information Coded In Alphanumeric.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _patricia_h_
#define _patricia_h_

#include "common.h"

#define PATRICIA_MAXBITS	256		/**< Maximum size of keys, in bits */

struct patricia;
typedef struct patricia patricia_t;

struct patricia_iter;
typedef struct patricia_iter patricia_iter_t;

typedef void (*patricia_cb_t)(void *key, size_t keybits, void *value, void *u);
typedef bool (*patricia_cbr_t)(void *key, size_t keybits, void *value, void *u);

/*
 * Public interface
 */

patricia_t *patricia_create(size_t maxbits);
void patricia_destroy(patricia_t *pt);
size_t patricia_count(const patricia_t *pt);
size_t patricia_max_keybits(const patricia_t *pt);
void patricia_insert(patricia_t *pt, const void *key, const void *value);
void patricia_insert_k(
	patricia_t *pt, const void *key, size_t keybits, const void *value);
bool patricia_remove(patricia_t *pt, const void *key);
bool patricia_remove_k(patricia_t *pt, const void *key, size_t keybits);
bool patricia_remove_closest(
	patricia_t *pt, const void *key, size_t keybits);
bool patricia_remove_furthest(
	patricia_t *pt, const void *key, size_t keybits);
bool patricia_contains(const patricia_t *pt, const void *key);
bool patricia_contains_k(
	const patricia_t *pt, const void *key, size_t keybits);
void *patricia_lookup(const patricia_t *pt, const void *key);
void *patricia_lookup_k(
	const patricia_t *pt, const void *key, size_t keybits);
bool patricia_lookup_extended(
	const patricia_t *pt, const void *key, void **keyptr, void **valptr);
bool patricia_lookup_extended_k(
	const patricia_t *pt, const void *key, size_t keybits,
	void **keyptr, void **valptr);
void patricia_foreach(const patricia_t *pt, patricia_cb_t cb, void *u);
size_t patricia_foreach_remove(patricia_t *pt, patricia_cbr_t cb, void *u);
bool patricia_lookup_best(
	const patricia_t *pt, const void *key, size_t keybits,
	void **keyptr, size_t *lenptr, void **valptr);
void *patricia_closest(const patricia_t *pt, const void *key);
bool patricia_closest_extended(
	const patricia_t *pt, const void *key, void **keyptr, void **valptr);
void *patricia_furthest(const patricia_t *pt, const void *key);
bool patricia_furthest_extended(
	const patricia_t *pt, const void *key,
	void **keyptr, void **valptr);

patricia_iter_t *patricia_tree_iterator(patricia_t *pt, bool forward);
patricia_iter_t *patricia_metric_iterator(patricia_t *pt,
	const void *key, bool forward);
patricia_iter_t *patricia_metric_iterator_lazy(
	patricia_t *pt, const void *key, bool forward);
bool patricia_iter_has_next(patricia_iter_t *iter);
void *patricia_iter_next_value(patricia_iter_t *iter);
bool patricia_iter_next(patricia_iter_t *iter,
	void **key, size_t *keybits, void **value);
void patricia_iterator_release(patricia_iter_t **iter_ptr);

void patricia_test(void);

#endif	/* _patricia_h_ */

/* vi: set ts=4 sw=4 cindent: */
