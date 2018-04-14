/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Win32 dynamic library patcher.
 *
 * The aim here is to make sure that each DLL using malloc() and friends
 * is dynamically patched to redirect the calls to xmalloc().
 *
 * We also supersede the LoadLibrary() calls to make sure each new DLL that
 * is brought in the process gets properly patched.
 *
 * The logic here was heavily inspired by the winpatcher code from nedmalloc()
 * which can be found at:
 *
 *		git://github.com/ned14/nedmalloc.git
 *
 * However, the code was reverse-engineered and completely rewritten for the
 * following reasons:
 *
 * 1- the code did not compile neatly within gtk-gnutella.
 * 2- we already have some low-level routines that we can peruse.
 * 3- we do not want a separate DLL, which would complicate our build process.
 * 4- we do not need all the #ifdef complexity in the original code
 *
 * And what matters is not the destination but the journey.  Rewriting this
 * logic helped me understand what was going on.  I hope the code is also
 * easier to understand the way I have rewritten it, and more readable for
 * people who, like me, are uncomfortable with mixed-case identifiers.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

/*
 * This whole file is only compiled under Windows.
 */

#ifdef MINGW32

#include <stdlib.h>
#include <windows.h>
#include <winnt.h>
#include <imagehlp.h>
#include <psapi.h>

#include "win32dlp.h"

#include "ascii.h"
#include "dump_options.h"
#include "atomic.h"
#include "bsearch.h"
#include "hashtable.h"
#include "log.h"
#include "omalloc.h"
#include "path.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "utf8.h"
#include "vmm.h"
#include "xmalloc.h"
#include "xsort.h"

#include "override.h"			/* Must be the last header included */

#if 0
#define WIN32DLP_DEBUG			/**< Trace patching activities */
#endif

/**
 * A module entry we wish to patch.
 */
typedef struct win32dlp_module {
	const char *name;			/* Module name */
	HMODULE addr;				/* Module address */
	uint32 flags;				/* Operating flags */
} win32dlp_module_t;

/**
 * Module flags.
 */
#define WIN32DLP_MODF_PATCHED	(1U << 0)	/* Module was patched already */
#define WIN32DLP_MODF_PROBED	(1U << 1)	/* Module was probed */
#define WIN32DLP_MODF_NO_IAT	(1U << 1)	/* Module has no IAT */

/**
 * A description of what to patch.
 */
typedef struct win32dlp_patch {
	struct win32dlp_replace {
		const char *name;		/* Replace this symbol */
		HMODULE base;			/* In this DLL */
		PROC addr;				/* Symbol address (NULL means: compute it) */
	} replace;
	win32dlp_module_t *modules;	/* List of modules where symbol is */
	struct win32dlp_with {
		const char *name;		/* Name of the routine */
		PROC addr;				/* Symbol address */
		bool careful;			/* Whether to dynamically validate "addr" */
	} with;
} win32dlp_patch_t;

/**
 * The VMM reserved region where we allocate memory from.
 */
static struct win32dlp_vmm {
	void *start;
	void *end;
} win32dlp_vmm;

typedef void (*win32dlp_free_t)(void *);
typedef size_t (*win32dlp_msize_t)(void *);

static win32dlp_free_t    win32dlp_sys_free;
static win32dlp_msize_t   win32dlp_sys_msize;

static const char win32dlp_unknown_name[] = "?";

static hash_table_t *win32dlp_loaded;	/* Loaded modules by handle (base) */
static hash_table_t *win32dlp_ignored;	/* Modules to ignore by handle */

static bool win32dlp_stop_freeing;
static bool win32dlp_in_place_only_used;

/**
 * Internal statistics collected.
 *
 * The AU64() fields are atomically updated and do not require a lock.
 */
static struct win32dlp_stats {
	AU64(trapped_malloc);
	AU64(trapped_calloc);
	AU64(trapped_realloc);
	AU64(trapped_free);
	AU64(trapped_msize);
	AU64(trapped_LoadLibraryA);
	AU64(trapped_LoadLibraryW);
	AU64(trapped_HeapAlloc);
	AU64(trapped_HeapReAlloc);
	AU64(trapped_HeapFree);
	AU64(trapped_HeapSize);
	AU64(passed_HeapAlloc);
	AU64(passed_HeapReAlloc);
	AU64(passed_HeapFree);
	AU64(passed_HeapSize);
	AU64(failed_HeapReAlloc);
	AU64(foreign_realloc);
	AU64(foreign_free);
	AU64(foreign_msize);
	AU64(foreign_HeapReAlloc);
	AU64(foreign_HeapFree);
	AU64(foreign_HeapSize);
	AU64(modules_initial);
	AU64(modules_loaded);
	AU64(modules_patched);
	AU64(entries_patched);
} win32dlp_stats;

#define WIN32DLP_STATS_INCX(x)		AU64_INC(&win32dlp_stats.x)
#define WIN32DLP_STATS_ADDX(x,n)	AU64_ADD(&win32dlp_stats.x, (n))

static void win32dlp_patch_loaded_modules(void);
static const struct win32dlp_with *win32dlp_with_compute(
	const win32dlp_module_t *m, const win32dlp_patch_t *how);

#ifdef WIN32DLP_DEBUG
#define win32dlp_debug(str) \
	s_rawdebug("%s(): " str " (%s)", G_STRFUNC, G_STRLOC)
#define win32dlp_debugf(fmt, ...) \
	s_rawdebug("%s(): " fmt " (%s)", G_STRFUNC, __VA_ARGS__, G_STRLOC)
#else
#define win32dlp_debug(str)		{}
#define win32dlp_debugf(...)	{}
#endif	/* WIN32DLP_DEBUG */

/**
 * Compute the module base address given a pointer within that module.
 *
 * The important assumption made here is that the whole DLL is going to
 * be memory-mapped by the kernel using a single memory region.
 *
 * @param p		a pointer within the DLL
 *
 * @return the base address of the DLL, or NULL if we cannot figure it out.
 */
static inline HMODULE
win32dlp_module_base(const void *p)
{
	return mingw_memstart(p);
}

/**
 * Is the pointer something we allocated through our VMM layer, and therefore
 * something that is likely to have been allocated via our xmalloc()?
 *
 * Note that, just because the pointer is susceptible of having been returned
 * by xmalloc(), it does not mean the pointer is valid.  For instance, if one
 * uses xmalloc(100) and then attempts to free the returned pointer + 10 bytes.
 * For sure, the pointer is valid and could have been returned by xmalloc(),
 * but it is not a valid pointer to hand-off to the xmalloc() layer.  However,
 * the layer has means to detect that a pointer is indeed a valid user one.
 *
 * @return whether the pointer falls in the VM space xmalloc() can use.
 */
static bool
win32dlp_via_xmalloc(const void *p)
{
	/*
	 * Quick win: if the pointer is within the reserved region, it was
	 * necessarily allocated via the VMM layer.  This is most likely to
	 * be the case.
	 */

	if G_LIKELY(
		ptr_cmp(win32dlp_vmm.start, p) <= 0 &&
		ptr_cmp(win32dlp_vmm.end, p) > 0
	)
		return TRUE;

	/*
	 * It's not in our reserved region, but it can be allocated via the VMM
	 * layer from the "unreserved" VM space.  In any case, this will be
	 * memory known to the VMM layer (i.e. identified as being mapped).
	 */

	return vmm_is_native_pointer(p);
}

/**
 * Ignore specified module.
 */
static inline void
win32dlp_ignore(HMODULE base)
{
	hash_table_insert(win32dlp_ignored, base, NULL);
}

/**
 * @return whether module is ignored.
 */
static inline bool
win32dlp_is_ignored(HMODULE base)
{
	return hash_table_contains(win32dlp_ignored, base);
}

/**
 * Register a new loaded module.
 *
 * @param file	the file path
 * @param addr	the loade module address
 */
static void
win32dlp_add_module(const char *file, HMODULE addr)
{
	/* The win32dlp_loaded hash table was locked by caller */

	if (hash_table_contains(win32dlp_loaded, addr)) {
		win32dlp_debugf("already had module \"%s\" at %p", file, addr);
	} else if (win32dlp_is_ignored(addr)) {
		win32dlp_debugf("module \"%s\" at %p is to be ignored", file, addr);
	} else {
		struct win32dlp_module *m;
		bool ok;

		OMALLOC0(m);
		m->name = ostrdup_readonly(filepath_basename(file));
		m->addr = addr;

		ok = hash_table_insert(win32dlp_loaded, addr, m);
		g_assert(ok);

		win32dlp_debugf("dynamically loaded module \"%s\" at %p", file, addr);

		WIN32DLP_STATS_INCX(modules_loaded);
	}
}

/**
 * Scan loaded modules and insert them into the table of loaded modules.
 *
 * This is done at the beginning to see which modules are present initially.
 * After that, we're trapping the module loading routines so we will know
 * that a new module has been loaded.
 */
static void
win32dlp_scan_modules(void)
{
	HMODULE *p, *last, modules[1024];
	HANDLE proc = GetCurrentProcess();
	bool ok;
	DWORD needed;

	/*
	 * There are two modules we want to ignore:
	 *
	 * - ourselves, the program, so that we do not supersede the routines
	 *   we call after trapping them (e.g. LoadLibraryW(), which we call
	 *   and whose symbol must keep pointing to the original)
	 *
	 * - the pthread DLL, which uses malloc() and will cause problems since
	 *   our locks always attempt to compute the thread small ID, which will
	 *   re-enter the pthread DLL if we have to call pthread_self() for
	 *   instance during our allocations, causing a deadly recursion.
	 */

	win32dlp_ignore(GetModuleHandle(NULL));
	win32dlp_ignore(win32dlp_module_base(pthread_self));

	ok = EnumProcessModules(proc, ARYLEN(modules), &needed);

	if (!ok) {
		s_error("%s(): EnumProcessModules() failed: %lu",
			G_STRFUNC, GetLastError());
	}

	g_assert(needed <= sizeof modules);		/* Can't store more anyway */

	last = &modules[needed / sizeof modules[0]];

	for (p = modules; ptr_cmp(p, last) < 0; p++) {
		struct win32dlp_module *m;
		const char *name = win32dlp_unknown_name;

		if (win32dlp_is_ignored(*p))
			continue;

#ifdef WIN32DLP_DEBUG
		{
			wchar_t wname[MAX_PATH + 1];
			char utf8_name[MAX_PATH];

			GetModuleBaseNameW(proc, *p, ARYLEN(wname) - 2);
			(void) utf16_to_utf8(wname, ARYLEN(utf8_name));
			utf8_name[MAX_PATH - 1] = '\0';
			name = ostrdup_readonly(utf8_name);
		}
#endif	/* WIN32DLP_DEBUG */

		OMALLOC0(m);
		m->name = name;
		m->addr = *p;

		ok = hash_table_insert(win32dlp_loaded, m->addr, m);
		g_assert(ok);
	}

	win32dlp_debugf("registered %zu initially loaded module%s",
		hash_table_count(win32dlp_loaded),
		plural(hash_table_count(win32dlp_loaded)));
}

/**
 * This is a specialized implementation of ImageDirectoryEntryToData() to
 * fetch the base and size of the Import Address Table (IAT) of the DLL.
 *
 * Since the DbgHelp module uses malloc() and we're trying to remap malloc()
 * by patching entries and avoid all usage of the C runtime malloc() if
 * possible, we cannot rely on the library function to do this job.
 *
 * @param base		this is the module base address (aka the module handle)
 * @param size		where size of the Import Address Table (IAT) is written.
 *
 * @return a pointer to the IAT, NULL on error.
 */
static void *
win32dlp_get_iat(const void *base, size_t *size)
{
	const IMAGE_DOS_HEADER *dos = base;
	const IMAGE_NT_HEADERS *pe = NULL;
	void *iat = NULL;
	size_t offset;
	const int dn = IMAGE_DIRECTORY_ENTRY_IMPORT;

	if (size != NULL)
		*size = 0;

	if (*(uint16 *) "MZ" == dos->e_magic)
		pe =  const_ptr_add_offset(dos, dos->e_lfanew);
	else
		pe = (IMAGE_NT_HEADERS *) dos;

	if (IMAGE_NT_SIGNATURE != pe->Signature)
		return NULL;

	offset = pe->OptionalHeader.DataDirectory[dn].VirtualAddress;

	if (offset != 0) {
		iat = ptr_add_offset_const(base, offset);
		if (size != NULL)
			*size = pe->OptionalHeader.DataDirectory[dn].Size;
	}

	return iat;
}

/**
 * Change the IAT entry, superseding it with a new function address.
 *
 * @param fn	the location within the IAT of the entry we want to supersede
 * @param addr	the superseding function address
 *
 * @return TRUE if OK, FALSE on error.
 */
static bool
win32dlp_iat_change(PROC *fn, PROC addr)
{
	MEMORY_BASIC_INFORMATION mbi;
	bool ok, changed = FALSE;

	ZERO(&mbi);

	if (0 == VirtualQuery(fn, VARLEN(mbi))) {
		errno = mingw_last_error();
		s_warning("%s(): cannot probe targeted address %p: %m", G_STRFUNC, fn);
		return FALSE;
	}

	if (0 == (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
		ok = VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
				PAGE_EXECUTE_WRITECOPY, &mbi.Protect);

		if (!ok) {
			errno = mingw_last_error();
			s_warning("%s(): cannot set write-copy for %'zu bytes at %p: %m",

				G_STRFUNC, (size_t) mbi.RegionSize, mbi.BaseAddress);
			return FALSE;
		}

		changed = TRUE;		/* Permission changed on region */
	}

	*fn = addr;		/* Update the IAT */
	atomic_mb();	/* Make sure new value is seen on all processors */

	/*
	 * According to MSDN, a FlushInstructionCache() is not necessary on x86
	 * and x64 CPU architectures.  It does not hurt to do it though.
	 */

	FlushInstructionCache(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize);

	if (changed) {
		ulong x;

		ok = VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &x);

		if (!ok) {
			s_message("%s(): cannot restore memory permissions for "
				"%'zu bytes at %p: %m",
				G_STRFUNC, (size_t) mbi.RegionSize, mbi.BaseAddress);
		}
	}

	return TRUE;
}

/**
 * Patch the Import Address Table (IAT) of the module.
 *
 * @param module	the module to patch
 * @param name		the name of the module providing the symbol to patch
 * @param how		the patch entry describing the symbol to replace
 *
 * @return amount of entries patched.
 */
static size_t
win32dlp_patch_iat(
	win32dlp_module_t *module, const char *name,
	const win32dlp_patch_t *how)
{
	IMAGE_IMPORT_DESCRIPTOR *di;
	size_t size, patched = 0;
	bool found = FALSE;

	if (module->flags & WIN32DLP_MODF_NO_IAT)
		return 0;		/* Known to have no IAT */

	/*
	 * Find the Import Address Table (IAT) of the module, if any present.
	 */

	di = win32dlp_get_iat(module->addr, &size);

	if (NULL == di) {
		module->flags |= WIN32DLP_MODF_NO_IAT;
		win32dlp_debugf("no IAT in module %p (%s)", module->addr, module->name);
		return 0;
	}

	/*
	 * Find all the import descriptors containing references to the module
	 * we want.
	 */

	for (/* empty */; di->Name != 0; di++) {
		const char *modname = const_ptr_add_offset(module->addr, di->Name);

		if (0 == ascii_strcasecmp(modname, name)) {
			IMAGE_THUNK_DATA *t;

			/*
			 * Found the module, now get the IAT for the functions imported
			 * from our wanted module.
			 */

			win32dlp_debugf("found IAT for DLL %s within module %p (%s)",
				name, module->addr, module->name);

			found = TRUE;
			t = ptr_add_offset(module->addr, di->FirstThunk);

			/*
			 * Now look for the thunk matching the function we want.
			 */

			for (/* empty */; t->u1.Function != 0; t++) {
				PROC *fn = (PROC *) &t->u1.Function;

				if G_UNLIKELY(*fn == how->replace.addr) {
					const struct win32dlp_with *with = &how->with;

					/*
					 * If they set the careful flag, see whether we have
					 * to specialize the replacement routine based on the
					 * module we're patching.
					 */

					if (with->careful) {
						with = win32dlp_with_compute(module, how);

						if G_UNLIKELY(with != &how->with) {
							win32dlp_debugf("superseded default replacement of "
								"%s() with %s(): using %s() for module %p (%s)",
								how->replace.name, how->with.name,
								with->name, module->addr, module->name);
						}
					}

					/*
					 * Update matching thunk.
					 */

					win32dlp_debugf("replacing %p for %s() with %p for %s() "
						"at %p within IAT of module %p (%s)",
						how->replace.addr, how->replace.name,
						how->with.addr, how->with.name, fn,
						module->addr, module->name);

					if (!win32dlp_iat_change(fn, with->addr)) {
						s_warning("%s(): cannot patch %p for %s() within "
							"IAT %p of module %p (%s): %m",
							G_STRFUNC, how->replace.addr, how->replace.name,
							fn, module->addr, module->name);
					} else {
						patched++;		/* Successfully patched */
					}
				}
			}
		}
	}

	if (!found) {
		win32dlp_debugf("no IAT for DLL %s within module %p (%s)",
			name, module->addr, module->name);
	}

	return patched;		/* Amount of entries patched */
}

/**
 * Apply replacement list to a loaded module.
 *
 * This is a hashtable iterator callback.
 */
static void
win32dlp_apply(const void *unused_key, void *value, void *data)
{
	struct win32dlp_module *m = value;		/* A loaded module */
	win32dlp_patch_t *p;
	size_t patched = 0;

	(void) unused_key;

	/*
	 * We're iterating over the hash table containing loaded modules, and
	 * this table is thread-safe.  Hence, we are the only thread that can
	 * access the patch table, and it is not necessary to lock it.
	 */

	g_assert(data != NULL);		/* There must be a patch table */

	/*
	 * If the module has already been fully patched, there's nothing to do.
	 */

	if G_LIKELY(m->flags & WIN32DLP_MODF_PATCHED)
		return;

	/*
	 * Loop over the patch, where each entry there describes a symbol to
	 * be replaced among a list of modules.
	 */

	for (p = data; p->replace.name != NULL; p++) {
		win32dlp_module_t *mp;
		g_assert(p->modules != NULL);

		/*
		 * The list of modules here describes the DLLs where the symbol
		 * to be replaced is located.
		 */

		for (mp = p->modules; mp->name != NULL; mp++) {
			/*
			 * Check whether module has been loaded, only done once per module.
			 */

			if (0 == (mp->flags & WIN32DLP_MODF_PROBED)) {
				mp->flags |= WIN32DLP_MODF_PROBED;
				mp->addr = GetModuleHandle(mp->name);
			}

			if (NULL == mp->addr)
				continue;				/* Module not loaded */

			if (NULL == p->replace.addr) {
				/*
				 * This module has been loaded, look whether it holds
				 * the routine we're trying to patch.  If it does, then
				 * we'll definitely bind the replacing of that symbol
				 * to the DLL we just discovered was loaded.
				 */

				p->replace.addr = GetProcAddress(mp->addr, p->replace.name);

				if (p->replace.addr != NULL) {
					p->replace.base = mp->addr;
					win32dlp_debugf("found %s() at %p in DLL %s",
						p->replace.name, p->replace.addr, mp->name);
				}
			}

			if (p->replace.addr != NULL)
				patched += win32dlp_patch_iat(m, mp->name, p);
		}
	}

	if (patched != 0) {
		WIN32DLP_STATS_INCX(modules_patched);
		WIN32DLP_STATS_ADDX(entries_patched, patched);
	}

	m->flags |= WIN32DLP_MODF_PATCHED;

	win32dlp_debugf("module at %p \"%s\" patched for %zu entr%s",
		m->addr, m->name, patched, plural_y(patched));
}

/***
 *** Trapped malloc()-related routines.
 ***/

static void *
win32dlp_malloc(size_t n)
{
	WIN32DLP_STATS_INCX(trapped_malloc);
	return xmalloc(n);
}

static void *
win32dlp_calloc(size_t n, size_t l)
{
	WIN32DLP_STATS_INCX(trapped_calloc);
	return xmalloc0(size_saturate_mult(n, l));
}

static void *
win32dlp_realloc(void *p, size_t n)
{
	size_t old_size;
	void *np;

	WIN32DLP_STATS_INCX(trapped_realloc);

	if (NULL == p || win32dlp_via_xmalloc(p))
		return xrealloc(p, n);

	WIN32DLP_STATS_INCX(foreign_realloc);
	win32dlp_debugf("foreign %p", p);

	/*
	 * This block was not allocated by xmalloc() and must have been
	 * allocated before we patched the DLL that is now calling this routine.
	 *
	 * We're allocating a new block via xmalloc() and copy the data over,
	 * then free-up the block.  However, it is imperative that we use the
	 * free() routine that the DLL which is calling us would normally have
	 * used before our patching.
	 *
	 * If we patched-up  their realloc() to lead us here, we have to assume
	 * we also patched-up their malloc() and can patch-up their free() to
	 * lead us back to our remapped routines!
	 *
	 * To know how much data there is to copy from the old block, we rely
	 * on the _msize() call to return the size of the allocated block by
	 * the malloc() layer used by the DLL, which must come from one of the
	 * Microsoft C runtime DLL.
	 */

	old_size = win32dlp_sys_msize(p);
	np = xmalloc(n);

	win32dlp_debugf("moving %'zu-byte old block at %p to %'zu-byte block at %p",
		old_size, p, n, np);

	g_assert(size_is_positive(old_size));

	memcpy(np, p, MIN(n, old_size));

	if G_LIKELY(!win32dlp_stop_freeing)
		win32dlp_sys_free(p);

	return np;
}

static void
win32dlp_free(void *p)
{
	WIN32DLP_STATS_INCX(trapped_free);

	if (NULL == p)
		return;		/* Seems OK for the MS C runtime to pass NULL to free() */

	if G_UNLIKELY(win32dlp_stop_freeing)
		return;

	if (win32dlp_via_xmalloc(p)) {
		xfree(p);
		return;
	}

	WIN32DLP_STATS_INCX(foreign_free);
	win32dlp_debugf("foreign %p", p);

	win32dlp_sys_free(p);
}

static size_t
win32dlp_msize(void *p)
{
	WIN32DLP_STATS_INCX(trapped_msize);

	if G_UNLIKELY(NULL == p)
		return 0;

	if (win32dlp_via_xmalloc(p))
		return xallocated(p);

	WIN32DLP_STATS_INCX(foreign_msize);
	win32dlp_debugf("foreign %p", p);

	return win32dlp_sys_msize(p);
}

/***
 *** Trapped DLL loading routines so that we can patch them as well.
 ***
 *** During loading of the new library, we must prevent any other thread
 *** from running or they could accidentally start using routines from
 *** that library before we have a chance to apply our patches.
 ***
 *** Unfortunately, this cannot be done without any loophole because we
 *** are not the kernel and cannot suspend all the threads from this process
 *** whilst we are loading the new module and patching up its IAT.
 ***
 *** Both LoadLibrary() interception routines use the same strategy:
 ***
 *** - they lock the table recording loaded modules, to funnel all the calls
 ***   to LoadLibrary().
 ***
 *** - they call thread_suspend_others() to ensure other threads will suspend
 ***   as soon as they can check for it.  For discovered threads, this is
 ***   only possible when they attempt to use malloc() and we already patched
 ***   up the IAT of the modules they are using.
 ***
 *** - they clear the "in system call" state for simplicity.  Sure we could
 ***   save the state and restore it, but the LoadLibrary() will only occur
 ***   once to get the DLL for a certain call and for that one intercepted
 ***   call, we will be in an unsafe state when we get an interrupt.
 ***
 *** This strategy assumes that we will always intercept the LoadLibrary()
 *** calls a module can make (most likely to happen) and that no code from
 *** the loaded library will be run until the intercepted LoadLibrary() calls
 *** returns (reasonable since this is necessarily synchronous wrt. the
 *** calling thread).
 ***/

static HMODULE WINAPI
win32dlp_LoadLibraryA(const char *file)
{
	HMODULE ret;

	WIN32DLP_STATS_INCX(trapped_LoadLibraryA);

	thread_in_syscall_reset();	/* About to take locks and allocate memory */

	hash_table_lock(win32dlp_loaded);
	thread_suspend_others(FALSE);

	ret = LoadLibraryA(file);

	if (ret != NULL) {
		win32dlp_add_module(file, ret);
		win32dlp_patch_loaded_modules();
	}

	thread_unsuspend_others();
	hash_table_unlock(win32dlp_loaded);

	return ret;
}

static HMODULE WINAPI
win32dlp_LoadLibraryW(const uint16 *file)
{
	HMODULE ret;

	WIN32DLP_STATS_INCX(trapped_LoadLibraryW);

	thread_in_syscall_reset();	/* About to take locks and allocate memory */

	hash_table_lock(win32dlp_loaded);
	thread_suspend_others(FALSE);

	ret = LoadLibraryW(file);

	if (ret != NULL) {
		char path[MAX_PATH];
		size_t conv;

		conv = utf16_to_utf8(file, ARYLEN(path));
		if (conv > sizeof path) {
			s_warning("%s(): cannot convert path from UTF-16 to UTF-8",
				G_STRFUNC);
			win32dlp_add_module(win32dlp_unknown_name, ret);
		} else {
			win32dlp_add_module(path, ret);
		}

		win32dlp_patch_loaded_modules();
	}

	thread_unsuspend_others();
	hash_table_unlock(win32dlp_loaded);

	return ret;
}

/***
 *** Trapped HeapAlloc() and HeapFree() which target the default process heap.
 ***
 *** The same logic as malloc() trapping above is used.  The only difference
 *** here is that we are only trapping calls that target the default process
 *** heap and let the others pass-through to the real routines.
 ***/

static HANDLE win32dlp_process_heap;

static LPVOID WINAPI
win32dlp_HeapAlloc(HANDLE h, DWORD flags, SIZE_T len)
{
	if G_UNLIKELY(NULL == win32dlp_process_heap)
		win32dlp_process_heap = GetProcessHeap();

	WIN32DLP_STATS_INCX(trapped_HeapAlloc);

	if G_UNLIKELY(h != win32dlp_process_heap) {
		WIN32DLP_STATS_INCX(passed_HeapAlloc);
		return HeapAlloc(h, flags, len);
	}

	if (HEAP_ZERO_MEMORY & flags)
		return xmalloc0(len);

	return xmalloc(len);
}

static LPVOID WINAPI
win32dlp_HeapReAlloc(HANDLE h, DWORD flags, LPVOID p, SIZE_T len)
{
	size_t old_size;
	void *np;

	if G_UNLIKELY(NULL == win32dlp_process_heap)
		win32dlp_process_heap = GetProcessHeap();

	WIN32DLP_STATS_INCX(trapped_HeapReAlloc);

	if G_UNLIKELY(h != win32dlp_process_heap) {
		WIN32DLP_STATS_INCX(passed_HeapReAlloc);
		return HeapReAlloc(h, flags, p, len);
	}

	/*
	 * Because xrealloc() does not have any support for
	 * HEAP_REALLOC_IN_PLACE_ONLY, we flag when it is being used
	 * in allocations performed on the default process heap.
	 */

	if G_UNLIKELY(HEAP_REALLOC_IN_PLACE_ONLY & flags)
		win32dlp_in_place_only_used = TRUE;

	if G_UNLIKELY(NULL == p) {
		if (HEAP_REALLOC_IN_PLACE_ONLY & flags)
			return NULL;
		if (HEAP_ZERO_MEMORY & flags)
			return xmalloc0(len);
		return xmalloc(len);
	}

	/*
	 * Note that since we do not support the HEAP_REALLOC_IN_PLACE_ONLY flag,
	 * we need to let the operation fail if the block was xmalloc()ed.
	 * The caller needs to be prepared for that situation since no heap can
	 * guarantee that the operation will always be able to succeed in-place.
	 */

	if (win32dlp_via_xmalloc(p)) {
		if G_UNLIKELY(HEAP_REALLOC_IN_PLACE_ONLY & flags) {
			WIN32DLP_STATS_INCX(failed_HeapReAlloc);
			return NULL;
		}

		old_size = (HEAP_ZERO_MEMORY & flags) ? xallocated(p) : 0;
		np = xrealloc(p, len);

		if ((HEAP_ZERO_MEMORY & flags) && len > old_size)
			memset(ptr_add_offset(np, old_size), 0, len - old_size);

		return np;
	}

	/*
	 * Handling a block previously allocated via HeapAlloc() on the heap.
	 *
	 * If HEAP_REALLOC_IN_PLACE_ONLY is used or if we cannot compute the
	 * proper size of the block, pass it to HeapReAlloc() to let it handle
	 * the situation it created.
	 */

	if G_UNLIKELY(HEAP_REALLOC_IN_PLACE_ONLY & flags) {
		WIN32DLP_STATS_INCX(passed_HeapReAlloc);
		return HeapReAlloc(h, flags, p, len);
	}

	old_size = HeapSize(h, 0, p);

	if G_UNLIKELY((size_t) -1 == old_size) {
		WIN32DLP_STATS_INCX(passed_HeapReAlloc);
		return HeapReAlloc(h, flags, p, len);
	}

	WIN32DLP_STATS_INCX(foreign_HeapReAlloc);

	np = xmalloc(len);
	memcpy(np, p, MIN(len, old_size));

	if ((HEAP_ZERO_MEMORY & flags) && len > old_size)
		memset(ptr_add_offset(np, old_size), 0, len - old_size);

	HeapFree(h, 0, p);		/* Old block, we now manage this memory */

	return np;
}

static BOOL WINAPI
win32dlp_HeapFree(HANDLE h, DWORD flags, LPVOID p)
{
	if G_UNLIKELY(NULL == win32dlp_process_heap)
		win32dlp_process_heap = GetProcessHeap();

	WIN32DLP_STATS_INCX(trapped_HeapFree);

	if G_UNLIKELY(h != win32dlp_process_heap) {
		WIN32DLP_STATS_INCX(passed_HeapFree);
		return HeapFree(h, flags, p);
	}

	if (win32dlp_via_xmalloc(p)) {
		xfree(p);
		return TRUE;
	}

	WIN32DLP_STATS_INCX(foreign_HeapFree);

	return HeapFree(h, flags, p);
}

static SIZE_T WINAPI
win32dlp_HeapSize(HANDLE h, DWORD flags, LPCVOID p)
{
	if G_UNLIKELY(NULL == win32dlp_process_heap)
		win32dlp_process_heap = GetProcessHeap();

	WIN32DLP_STATS_INCX(trapped_HeapSize);

	if G_UNLIKELY(h != win32dlp_process_heap) {
		WIN32DLP_STATS_INCX(passed_HeapSize);
		return HeapSize(h, flags, p);
	}

	if G_UNLIKELY(NULL == p)
		return 0;

	if (win32dlp_via_xmalloc(p))
		return xallocated(p);

	WIN32DLP_STATS_INCX(foreign_HeapSize);

	return HeapSize(h, flags, p);
}

/***
 *** Patch table definition.
 ***/

/* Avoid warnings if already defined in some global header */
#undef MODULE
#undef REPLACE
#undef WITH
#undef CARE
#undef IN

#define MODULE(x)		{ x, NULL, 0 }
#define REPLACE(x)		{ # x, NULL, NULL }
#define WITH(x)			{ # x, (PROC) x, FALSE }	/* Plain, static mapping */
#define CARE(x)			{ # x, (PROC) x, TRUE }		/* Uses "careful" trap */
#define IN(x)			win32dlp_ ## x

#define REPLACE_NULL	{ NULL, NULL, NULL }
#define WITH_NULL		{ NULL, NULL, FALSE }
#define IN_NULL			NULL

/**
 * Microsoft's C runtime DLLs (names are case-insensitive).
 */
static win32dlp_module_t win32dlp_msvcr[] = {
	MODULE("msvcr20.dll"),
	MODULE("msvcr40.dll"),
	MODULE("msvcr70.dll"),
	MODULE("msvcr71.dll"),
	MODULE("msvcr80.dll"),
	MODULE("msvcr90.dll"),
	MODULE("msvcr100.dll"),
	MODULE("msvcrt.dll"),
	MODULE(NULL),		/* Trailing sentinel */
};

/**
 * Kernel access DLL.
 */
static win32dlp_module_t win32dlp_kernel[] = {
	MODULE("kernel32.dll"),
	MODULE(NULL),		/* Trailing sentinel */
};

/**
 * What we are patching here.
 */
static win32dlp_patch_t win32dlp_patch[] = {
	{ REPLACE(malloc),       IN(msvcr),  WITH(win32dlp_malloc)       },
	{ REPLACE(calloc),       IN(msvcr),  WITH(win32dlp_calloc)       },
	{ REPLACE(realloc),      IN(msvcr),  WITH(win32dlp_realloc)      },
	{ REPLACE(free),         IN(msvcr),  WITH(win32dlp_free)         },
	{ REPLACE(_msize),       IN(msvcr),  WITH(win32dlp_msize)        },
	{ REPLACE(LoadLibraryA), IN(kernel), WITH(win32dlp_LoadLibraryA) },
	{ REPLACE(LoadLibraryW), IN(kernel), WITH(win32dlp_LoadLibraryW) },
	{ REPLACE(HeapAlloc),    IN(kernel), WITH(win32dlp_HeapAlloc)    },
	{ REPLACE(HeapReAlloc),  IN(kernel), WITH(win32dlp_HeapReAlloc)  },
	{ REPLACE(HeapFree),     IN(kernel), WITH(win32dlp_HeapFree)     },
	{ REPLACE(HeapSize),     IN(kernel), WITH(win32dlp_HeapSize)     },
	{ REPLACE_NULL,          IN_NULL,    WITH_NULL                   },
};

/**
 * This is an apply callback that is used to supersede the hardwired patch
 * mapping in some particular cases.
 *
 * @param m		the module which we are patching
 * @param how	the description of the default patching we want to do
 *
 * @return the target for patching.
 */
static const struct win32dlp_with *
win32dlp_with_compute(const win32dlp_module_t *m, const win32dlp_patch_t *how)
{
	g_assert(m != NULL);
	g_assert(how != NULL);

	/*
	 * Can use m->addr and how->with.add to test for superseding a given
	 * routine for a special module.  For instance, to change the mapping
	 * of "fn" in a given module whose handle is "modulehandle" and replace
	 * the normal "fn" mapping to "special_fn", say something like:
	 *
	 * static struct win32dlp_with superseded = WITH(special_fn);
	 *
	 * if (m->addr == modulehandle && 0 == ptr_cmp(fn, how->with.addr))
	 *     return &superseded;
	 */

	/* EMPTY */

	/*
	 * Keep original patching request if none of the above tests match.
	 */

	return &how->with;		/* Use original patching */
}

/**
 * Patch all loaded modules.
 */
static void
win32dlp_patch_loaded_modules(void)
{
	hash_table_foreach(win32dlp_loaded, win32dlp_apply, win32dlp_patch);
}

/**
 * Find the original routine in the patch table (the replace.addr field).
 *
 * @param patch		the patch holding the routines to replace
 * @param name		the routine we're looking for
 *
 * @return the address we figured out for the routine name.
 */
static void *
win32dlp_patch_find(const win32dlp_patch_t *patch, const char *name)
{
	const win32dlp_patch_t *p;

	/*
	 * This is done a limited amount of time at startup, a linear lookup
	 * will be sufficient!
	 */

	for (p = patch; p->replace.name != NULL; p++) {
		if (0 == strcmp(p->replace.name, name))
			return p->replace.addr;
	}

	s_error("%s(): routine %s() not found in supplied patch", G_STRFUNC, name);
}

/**
 * Enable malloc by recording the original address of free() and _msize().
 */
static void
win32dlp_malloc_enable(const win32dlp_patch_t *patch)
{
	/*
	 * To enable foreign malloc() block (i.e. blocks allocated by a DLL
	 * before we patched its IAT and which would then be handed to our
	 * redefined realloc() and free() routines), we need to be able to
	 * do two things:
	 *
	 * - we need to be able to compute the size of the allocated block by
	 *   the foreign C runtime.  Fortunately, the C runtime has _msize() to
	 *   allow us to do just that.
	 *
	 * - we need to be able to call the original C runtime free() routine to
	 *   dispose these allocate blocks.
	 *
	 * Therefore we capture their original address, which we computed in the
	 * patch structure to be able to precisely recognize the entries in the
	 * IAT to supersede them with our version!
	 */

	win32dlp_sys_free  = win32dlp_patch_find(patch, "free");
	win32dlp_sys_msize = win32dlp_patch_find(patch, "_msize");

	/*
	 * The routine must be found since we already patched all the DLLs loaded
	 * so far.  Otherwise, we would not be able to go very far.
	 */

	g_assert(win32dlp_sys_free != NULL);
	g_assert(win32dlp_sys_msize != NULL);
}

/**
 * Notified that the process is exiting, therefore you can stop freeing memory.
 */
void
win32dlp_exiting(void)
{
	win32dlp_stop_freeing = TRUE;
}

/**
 * Plug in the Win32 patching code.
 *
 * @param reserved		start of the VMM reserved region
 * @param size			length of the VMM reserved region
 */
void
win32dlp_init(void *reserved, size_t size)
{
	tm_t start, end;

	g_assert_log(NULL == win32dlp_loaded,
		"%s(): can only be called once", G_STRFUNC);

	win32dlp_debug("Win32 dynamic library patching enabled");

	/*
	 * Warning: this is called very early during the process startup, and as
	 * such we need to make sure the auto-initialization of the various layers
	 * does not create a deadlock.
	 *
	 * This call ensures the thread layer is properly initialized, which must
	 * happen before we invoke omalloc(), otherwise we're going to deadlock
	 * as omalloc() takes a spinlock, tries to register it in the thread
	 * element which then attempts to omalloc() the main lock stack in the
	 * main thread element!
	 *
	 * Note that we are using an experimental omalloc_ext() routine now,
	 * which uses hidden spinlocks in omalloc() to precisely avoid the above
	 * pitfall.  This is me being paranoid.
	 */

	tm_now_exact(&start);		/* Side effect: initializes thread layer */

	win32dlp_debug("discovered main thread");

	/*
	 * This is the region in the VM space that we have reserved for our VMM
	 * layer to allocate memory from.  Most of the core memory is going to
	 * be allocted from that region.  If we're given a pointer falling outside
	 * that range, we'll still need to use vmm_is_native_pointer() since there
	 * can be non-hinted memory allocations -- see mingw_valloc().
	 */

	win32dlp_vmm.start = reserved;
	win32dlp_vmm.end   = ptr_add_offset(reserved, size);

	win32dlp_debugf("VMM allocated segment is [%p, %p[",
		win32dlp_vmm.start, win32dlp_vmm.end);

	/*
	 * This table is used to track the modules we have already loaded
	 * successfully, so that we may quickly skip them later when we
	 * re-attempt to patch modules after we have loaded new ones.
	 */

	win32dlp_loaded = hash_table_new();
	hash_table_thread_safe(win32dlp_loaded);

	/*
	 * This hash table is used to track the modules for which we do not
	 * want to do any patching.
	 */

	win32dlp_ignored = hash_table_new();

	win32dlp_debug("scanning and patching loaded modules...");

	win32dlp_scan_modules();
	WIN32DLP_STATS_ADDX(modules_initial, hash_table_count(win32dlp_loaded));
	win32dlp_patch_loaded_modules();

	win32dlp_debug("enabling foreign malloc() blocks...");

	win32dlp_malloc_enable(win32dlp_patch);

	tm_now_exact(&end);

	win32dlp_debugf("all done in %.03f secs.", tm_elapsed_f(&end, &start));
}

/**
 * Dump win32 patcher statistics to specified log agent as xmalloc() stats.
 *
 * These are appended to xmalloc() stats on Windows so that we can monitor
 * how successful the remapping strategy is.
 */
void
win32dlp_dump_stats_log(logagent_t *la, unsigned options)
{
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

#define DUMP(x) G_STMT_START {								\
	uint64 v = AU64_VALUE(&win32dlp_stats.x);				\
	log_info(la, "XM win32dlp_%s = %s", #x,					\
		uint64_to_string_grp(v, groupped));					\
} G_STMT_END

	DUMP(trapped_malloc);
	DUMP(trapped_calloc);
	DUMP(trapped_realloc);
	DUMP(trapped_free);
	DUMP(trapped_msize);
	DUMP(trapped_LoadLibraryA);
	DUMP(trapped_LoadLibraryW);
	DUMP(trapped_HeapAlloc);
	DUMP(trapped_HeapReAlloc);
	DUMP(trapped_HeapFree);
	DUMP(trapped_HeapSize);
	DUMP(passed_HeapAlloc);
	DUMP(passed_HeapReAlloc);
	DUMP(passed_HeapFree);
	DUMP(passed_HeapSize);
	DUMP(foreign_realloc);
	DUMP(foreign_free);
	DUMP(foreign_msize);
	DUMP(foreign_HeapReAlloc);
	DUMP(foreign_HeapFree);
	DUMP(foreign_HeapSize);
	DUMP(failed_HeapReAlloc);
	DUMP(modules_initial);
	DUMP(modules_loaded);
	DUMP(modules_patched);
	DUMP(entries_patched);
}

/**
 * Called to log win32dlp status on the specified log agent.
 */
void
win32dlp_show_settings_log(logagent_t *la)
{
	size_t patched = AU64_VALUE(&win32dlp_stats.modules_patched);
	size_t loaded = AU64_VALUE(&win32dlp_stats.modules_loaded);
	size_t initial = AU64_VALUE(&win32dlp_stats.modules_initial);

	log_info(la, "win32 dynamic linker patched %zu module%s out of %zu+%zu=%zu",
		patched, plural(patched), initial, loaded, initial + loaded);

	if (win32dlp_in_place_only_used)
		log_warning(la, "HeapReAlloc() is using HEAP_REALLOC_IN_PLACE_ONLY");
 }

#endif	/* MINGW32 */

/* vi: set ts=4 sw=4 cindent: */
