/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * Random numbers.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _random_h_
#define _random_h_

#include "common.h"

/*
 * Random numbers
 */

void random_init(void);
uint32 random_value(uint32 max) WARN_UNUSED_RESULT;
uint64 random64_value(uint64 max) WARN_UNUSED_RESULT;
ulong random_ulong_value(ulong max) WARN_UNUSED_RESULT;
uint32 random_u32(void) WARN_UNUSED_RESULT;
uint64 random_u64(void) WARN_UNUSED_RESULT;
ulong random_ulong(void) WARN_UNUSED_RESULT;
void random_bytes(void *dst, size_t size);
void random_strong_bytes(void *dst, size_t size);
void random_key_bytes(void *dst, size_t size);
void random_bytes_with(random_fn_t rf, void *dst, size_t size);
uint32 random_cpu_noise(void);
void random_collect(void);
void random_pool_append(void *buf, size_t len);
void random_add(const void *data, size_t datalen);
double random_double_generate(random_fn_t rf) WARN_UNUSED_RESULT;
double random_double(void) WARN_UNUSED_RESULT;
uint32 random_upto(random_fn_t rf, uint32 max) WARN_UNUSED_RESULT;
uint64 random64_upto(random64_fn_t rf, uint64 max) WARN_UNUSED_RESULT;

uint32 random_strong(void);		/* Exported for tests, mostly */

/*
 * Notification of new randomness addtion.
 */

typedef void (*random_added_listener_t)(void);

void random_added_listener_add(random_added_listener_t l);
void random_added_listener_remove(random_added_listener_t l);

struct logagent;
struct sha1;

void random_dump_stats(void);
void random_dump_stats_log(struct logagent *la, unsigned options);
void random_stats_digest(struct sha1 *digest);

#endif /* _random_h_ */

/* vi: set ts=4 sw=4 cindent: */
