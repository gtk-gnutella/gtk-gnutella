/*
 * Copyright (c) 2011 Raphael Manfredi
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
 * Chunk memory allocator for objects that are never resized nor freed
 * individually.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _ckalloc_h_
#define _ckalloc_h_

struct ckhunk;
typedef struct ckhunk ckhunk_t;

/*
 * Public interface.
 */

ckhunk_t *ck_init(size_t size, size_t reserved);
ckhunk_t *ck_init_not_leaking(size_t size, size_t reserved);
void ck_destroy(ckhunk_t *ck);
void ck_destroy_null(ckhunk_t **ck_ptr);
void *ck_alloc(ckhunk_t *ck, size_t len);
void *ck_alloc_critical(ckhunk_t *ck, size_t len);
bool ck_used(const ckhunk_t *ck);
void *ck_save(const ckhunk_t *ck);
void ck_restore(ckhunk_t *ck, void *saved);
void ck_free_all(ckhunk_t *ck);
void *ck_copy(ckhunk_t *ck, const void *p, size_t size);
char *ck_strdup(ckhunk_t *ck, const char *str);
void ck_readonly(ckhunk_t *ck);
void ck_writable(ckhunk_t *ck);
void *ck_alloc_readonly(ckhunk_t *ck, size_t len);
void *ck_copy_readonly(ckhunk_t *ck, const void *p, size_t size);
char *ck_strdup_readonly(ckhunk_t *ck, const char *str);
bool ck_shrink(ckhunk_t *ck, size_t size);
bool ck_memcpy(ckhunk_t *ck, void *dest, const void *src, size_t size);
bool ck_is_readonly(ckhunk_t *ck);

#endif /* _ckalloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
