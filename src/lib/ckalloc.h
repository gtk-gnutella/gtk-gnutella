/*
 * $Id$
 *
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

ckhunk_t *ckinit(size_t size, size_t reserved);
ckhunk_t *ckinit_not_leaking(size_t size, size_t reserved);
void ckdestroy_null(ckhunk_t **ck_ptr);
void *ckalloc(ckhunk_t *ck, size_t len);
void *ckalloc_critical(ckhunk_t *ck, size_t len);
gboolean ckused(const ckhunk_t *ck);
void *cksave(const ckhunk_t *ck);
void ckrestore(ckhunk_t *ck, void *saved);
void ckfree_all(ckhunk_t *ck);
void *ckcopy(ckhunk_t *ck, const void *p, size_t size);
char *ckstrdup(ckhunk_t *ck, const char *str);
void ckreadonly(ckhunk_t *ck);
void *ckallocro(ckhunk_t *ck, size_t len);
void *ckcopyro(ckhunk_t *ck, const void *p, size_t size);
char *ckstrdupro(ckhunk_t *ck, const char *str);

#endif /* _ckalloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
