/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
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
 * Gnutella DHT "publish" interface.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

RCSID("$Id$")

#include "pdht.h"
#include "gdht.h"
#include "share.h"
#include "ggep.h"
#include "ggep_type.h"
#include "sockets.h"			/* For socket_listen_port() */
#include "tls_common.h"			/* For tls_enabled() */

#include "if/dht/kademlia.h"
#include "if/dht/lookup.h"
#include "if/dht/knode.h"
#include "if/dht/value.h"
#include "if/dht/publish.h"
#include "if/dht/stable.h"
#include "if/core/fileinfo.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/misc.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define PDHT_ALOC_MAJOR		0	/**< We generate v0.1 "ALOC" values */
#define PDHT_ALOC_MINOR		1

#define PDHT_BG_PERIOD		60000	/**< 1 minute, in ms */
#define PDHT_BG_MAX_RUNS	3		/**< Max amount of background attempts */

/**
 * Hash table holding all the pending file publishes by SHA1.
 */
static GHashTable *aloc_publishes;		/* SHA1 -> pdht_publish_t */

typedef enum { PDHT_PUBLISH_MAGIC = 0x680182c5U } pdht_magic_t;

typedef enum {
	PDHT_T_ALOC = 0,			/**< ALOC value: shared files */
	PDHT_T_PROX,				/**< PROX value: push-proxies */

	PDHT_T_MAX					/**< Amount of publishing types */
} pdht_type_t;

/**
 * Background context.
 *
 * Background publishing is created when a STORE request is issued and
 * there are nodes which reported non-specific error conditions that do
 * not enable us to know why the STORE attempt failed.
 */
struct pdht_bg {
	guint16 *status;			/**< Consolidated STORE statuses */
	const lookup_rs_t *rs;		/**< STORE lookup path */
	cevent_t *ev;				/**< Scheduling for background store */
	unsigned published;			/**< Consolidated amount of publishes */
	unsigned candidates;			/**< Initial amount of STORE roots */
	int delay;					/**< Background delay used last iteration */
	int runs;					/**< Completed background runs */
};

/**
 * Publishing context.
 */
typedef struct pdht_publish {
	pdht_magic_t magic;
	pdht_type_t type;
	pdht_cb_t cb;				/**< Callback to invoke when finished */
	gpointer arg;				/**< Callback argument */
	const kuid_t *id;			/**< Publishing key (atom) */
	publish_t *pb;				/**< The publishing request */
	dht_value_t *value;			/**< The value being published */
	struct pdht_bg *bg;			/**< For backgrounded STORE requests */
	union {
		struct pdht_aloc {			/**< Context for ALOC publishing */
			const sha1_t *sha1;		/**< SHA1 of the file being published */
			shared_file_t *sf;		/**< Published file entry, for logs */
		} aloc;
	} u;
	guint32 flags;				/**< Operating flags */
} pdht_publish_t;

static inline void
pdht_publish_check(const pdht_publish_t *pp)
{
	g_assert(pp != NULL);
	g_assert(PDHT_PUBLISH_MAGIC == pp->magic);
}

/**
 * Operating flags for publishing context.
 */
#define PDHT_F_CANCELLING	(1U << 0)	/**< Explicitly cancelling */
#define PDHT_F_BACKGROUND	(1U << 1)	/**< Background publishing */

static void pdht_bg_publish(cqueue_t *unused_cq, gpointer obj);

/**
 * English version of the publish type.
 */
static const char *
pdht_type_to_string(pdht_type_t type)
{
	switch (type) {
	case PDHT_T_ALOC:	return "ALOC";
	case PDHT_T_PROX:	return "PROX";
	case PDHT_T_MAX:	break;
	}

	return "UNKNOWN";
}

/**
 * Allocate a background publishing context.
 */
static struct pdht_bg *
pdht_bg_alloc(const lookup_rs_t *rs, const guint16 *status,
	unsigned published, unsigned candidates)
{
	struct pdht_bg *pbg;

	pbg = walloc0(sizeof *pbg);
	pbg->rs = lookup_result_refcnt_inc(rs);
	pbg->published = published;
	pbg->candidates = candidates;
	pbg->status = wcopy(status,
		lookup_result_path_length(rs) * sizeof *pbg->status);

	return pbg;
}

/**
 * Free background publishing context and nullify pointer.
 */
static void
pdht_bg_free_null(struct pdht_bg **pbg_ptr)
{
	struct pdht_bg *pbg = *pbg_ptr;

	if (pbg != NULL) {
		cq_cancel(callout_queue, &pbg->ev);
		WFREE_NULL(pbg->status,
			lookup_result_path_length(pbg->rs) * sizeof *pbg->status);
		lookup_result_free(pbg->rs);
		*pbg_ptr = NULL;
	}
}

/**
 * Free publishing context.
 */
static void
pdht_free_publish(pdht_publish_t *pp, gboolean do_remove)
{
	pdht_publish_check(pp);

	if (do_remove && pp->pb != NULL) {
		publish_cancel(pp->pb, FALSE);
		pp->pb = NULL;
	}

	if (pp->value != NULL)
		dht_value_free(pp->value, TRUE);

	pdht_bg_free_null(&pp->bg);

	switch (pp->type) {
	case PDHT_T_ALOC:
		if (do_remove)
			g_hash_table_remove(aloc_publishes, pp->u.aloc.sha1);
		atom_sha1_free(pp->u.aloc.sha1);
		shared_file_unref(&pp->u.aloc.sf);
		break;
	case PDHT_T_PROX:
		/* XXX */
		break;
	case PDHT_T_MAX:
		g_assert_not_reached();
	}

	kuid_atom_free(pp->id);
	wfree(pp, sizeof *pp);
}

static const char *pdht_errstr[] = {
	"OK",									/**< PDHT_E_OK */
	"Value is popular",						/**< PDHT_E_POPULAR */
	"Error during node lookup",				/**< PDHT_E_LOOKUP */
	"Node lookup expired",					/**< PDHT_E_LOOKUP_EXPIRED */
	"SHA1 of shared file not available",	/**< PDHT_E_SHA1 */
	"Value publishing still pending",		/**< PDHT_E_PENDING */
	"File no longer shared",				/**< PDHT_E_NOT_SHARED */
	"Could not build GGEP DHT value",		/**< PDHT_E_GGEP */
	"Got no acknowledgement at all",		/**< PDHT_E_NONE */
	"Cancelled",							/**< PDHT_E_CANCELLED */
	"UDP queue clogged",					/**< PDHT_E_UDP_CLOGGED */
	"Publish expired",						/**< PDHT_E_PUBLISH_EXPIRED */
	"Publish error",						/**< PDHT_E_PUBLISH_ERROR */
};

/**
 * English representation of an error code.
 */
const char *
pdht_strerror(pdht_error_t code)
{
	STATIC_ASSERT(G_N_ELEMENTS(pdht_errstr) == PDHT_E_MAX);

	if (UNSIGNED(code) >= G_N_ELEMENTS(pdht_errstr))
		return "invalid PDHT error code";

	return pdht_errstr[code];
}

/**
 * Report publishing error.
 */
static void
pdht_publish_error(pdht_publish_t *pp, pdht_error_t code)
{
	pdht_info_t pinfo;

	pdht_publish_check(pp);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_message("PDHT aborting %s publish for %s: %s",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			pdht_strerror(code));
	}

	pinfo.roots = 0;
	pinfo.all_roots = 0;
	pinfo.path_len = 0;
	pinfo.can_bg = FALSE;
	pinfo.presence = 0.0;

	(*pp->cb)(pp->arg, code, &pinfo);
	pdht_free_publish(pp, pp->id != NULL);
}

/**
 * Callback when publish_value() is done.
 */
static void
pdht_publish_done(gpointer arg,
	publish_error_t code, const publish_info_t *info)
{
	pdht_publish_t *pp = arg;
	pdht_error_t status;
	unsigned published = info->published;
	unsigned candidates = info->candidates;
	gboolean can_bg = TRUE;
	pdht_info_t pinfo;

	pdht_publish_check(pp);

	pp->pb = NULL;

	switch (code) {
	case PUBLISH_E_OK:			status = PDHT_E_OK; break;
	case PUBLISH_E_CANCELLED:	status = PDHT_E_CANCELLED; break;
	case PUBLISH_E_UDP_CLOGGED:	status = PDHT_E_UDP_CLOGGED; break;
	case PUBLISH_E_EXPIRED:		status = PDHT_E_PUBLISH_EXPIRED; break;
	case PUBLISH_E_POPULAR:		status = PDHT_E_POPULAR; break;
	case PUBLISH_E_NONE:		status = PDHT_E_NONE; break;
	case PUBLISH_E_ERROR:
	case PUBLISH_E_MAX:
		status = PDHT_E_PUBLISH_ERROR;
		break;
	}

	/*
	 * If after our max background publishing attempts we did not manage
	 * to store the data to any of the nodes, and provided we had KDA_K
	 * candidates at the beginning and more than KDA_K/2 candidates in our last
	 * run, it is safe to assume that the file is popular enough and that
	 * the real cause for getting generic errors is that the key is full in
	 * all the k-closest nodes.
	 */

	if (
		PUBLISH_E_OK == code &&
		pp->bg != NULL && pp->bg->runs >= PDHT_BG_MAX_RUNS
	) {
		unsigned roots = pp->bg->candidates;	/* Initial amount of roots */
		if (
			KDA_K == roots && info->candidates >= KDA_K/2 &&
			0 == info->published
		) {
			if (GNET_PROPERTY(publisher_debug) > 1) {
				g_message("PDHT assuming %s %s is a popular key",
					pdht_type_to_string(pp->type), kuid_to_string(pp->id));
			}
			status = PDHT_E_POPULAR;
		}
	}

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_message("PDHT ending %s%s publish for %s (%u publish%s): %s",
			(pp->flags & PDHT_F_BACKGROUND) ? "background " : "",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			info->published, 1 == info->published ? "" : "es",
			publish_strerror(code));
	}

	/*
	 * Consolidate the total amount of nodes to which publishing was done.
	 */

	if (pp->bg != NULL) {
		published += pp->bg->published;
		pp->bg->published = published;
		candidates = pp->bg->candidates;	/* Initial amount of STORE roots */
	}

	/*
	 * If the publishing layer published to all the candidate roots it could
	 * find, then there's no need continuing to background STORES.
	 */

	if (info->published >= info->candidates) {
		if (GNET_PROPERTY(publisher_debug) > 1) {
			g_message("PDHT no more nodes to background publish %s for %s",
				pdht_type_to_string(pp->type), kuid_to_string(pp->id));
		}
		can_bg = FALSE;		/* Published to all available k-closest roots */
	} else if (pp->bg != NULL && pp->bg->runs >= PDHT_BG_MAX_RUNS) {
		if (GNET_PROPERTY(publisher_debug) > 1) {
			g_message("PDHT reached max background %s publish attempts for %s",
				pdht_type_to_string(pp->type), kuid_to_string(pp->id));
		}
		can_bg = FALSE;		/* Reached max amount of retries */
	}

	/*
	 * If the upper layer accepts the publishing, then we're done.
	 */

	pinfo.roots = info->published;
	pinfo.all_roots = published;
	pinfo.path_len = candidates;
	pinfo.can_bg = can_bg;
	pinfo.presence = stable_store_presence(
		DHT_VALUE_REPUBLISH, info->rs, info->status);

	if ((*pp->cb)(pp->arg, status, &pinfo)) {
		if (pp->flags & PDHT_F_CANCELLING)
			return;
		goto terminate;
	}

	/*
	 * Upper layer wants us to continue publishing in the background,
	 * calling back after each subsequent iteration to report on progress.
	 *
	 * The background attempt is delayed for a while, and each time we
	 * actually schedule it in the future, we double the period.
	 */

	if (!can_bg)
		goto terminate;		/* Cannot continue background STORE */

	if (pp->bg != NULL) {
		g_assert(pp->bg->runs < PDHT_BG_MAX_RUNS);	/* Checked above */
		pp->bg->delay *= 2;
		memcpy(pp->bg->status, info->status,
			lookup_result_path_length(info->rs) * sizeof *info->status);
	} else {
		pp->flags |= PDHT_F_BACKGROUND;
		pp->bg = pdht_bg_alloc(info->rs, info->status,
			published, info->candidates);
		pp->bg->delay = PDHT_BG_PERIOD;
	}

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_message("PDHT will start background %s publish for %s in %d secs",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			pp->bg->delay / 1000);
	}

	pp->bg->ev = cq_insert(callout_queue, pp->bg->delay, pdht_bg_publish, pp);
	return;

terminate:
	pdht_free_publish(pp, TRUE);
}

/**
 * Callout queue callback to launch a background publish.
 */
static void
pdht_bg_publish(cqueue_t *unused_cq, gpointer obj)
{
	pdht_publish_t *pp = obj;

	(void) unused_cq;

	pdht_publish_check(pp);
	g_assert(pp->bg != NULL);
	g_assert(NULL == pp->pb);

	pp->bg->ev = NULL;
	pp->bg->runs++;

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_message("PDHT starting background %s publish for %s (run #%d)",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			pp->bg->runs);
	}

	switch (pp->type) {
	case PDHT_T_ALOC:
		pp->pb = publish_value_background(dht_value_clone(pp->value),
			pp->bg->rs, pp->bg->status, pdht_publish_done, pp);
		break;
	case PDHT_T_PROX:
		/* XXX */
		break;
	case PDHT_T_MAX:
		g_assert_not_reached();
	}
}

/**
 * Generate a DHT "ALOC" value to publish the shared file.
 *
 * @return NULL if problems during GGEP encoding, the DHT value otherwise.
 */
static dht_value_t *
pdht_get_aloc(const shared_file_t *sf, const kuid_t *key)
{
	void *value;
	ggep_stream_t gs;
	int ggep_len;
	gboolean ok;
	const struct tth *tth;
	dht_value_t *aloc;
	knode_t *our_knode;

	/*
	 * An ALOC value bears the following GGEP keys:
	 *
	 * client-id		the servent's GUID as raw 16 bytes
	 * firewalled		1 byte boolean: whether we are TCP-firewalled
	 * port				the port where file can be requested
	 * length			the length of the file, coded as in "LF"
	 * avail			length available, only set when file is partial
	 * tls				no payload, presence means TLS support
	 * ttroot			the TTH root of the file, as raw data
	 * HNAME			the host's DNS name, if known (as in query hits)
	 *
	 * For LimeWire, the first 4 keys are mandatory for ALOC v0.1.
	 * Stupidly enough for the "firewalled" key, which could have been made
	 * optional like "tls", but this is LimeWire's design choice (interns?).
	 */

	value = walloc(DHT_VALUE_MAX_LEN);
	ggep_stream_init(&gs, value, DHT_VALUE_MAX_LEN);
	
	ok = ggep_stream_pack(&gs, GGEP_NAME(client_id),
		GNET_PROPERTY(servent_guid), GUID_RAW_SIZE, 0);

	{
		guint8 fw = booleanize(GNET_PROPERTY(is_firewalled));
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(firewalled), &fw, 1, 0);
	}

	{
		char buf[sizeof(guint64)];
		int len;

		len = ggept_filesize_encode(shared_file_size(sf), buf);
		g_assert(len > 0 && UNSIGNED(len) <= sizeof buf);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(length), buf, len, 0);
	}

	if (shared_file_is_partial(sf)) {
		fileinfo_t *fi = shared_file_fileinfo(sf);

		if (shared_file_size(sf) != fi->done) {
			char buf[sizeof(guint64)];
			int len;

			len = ggept_filesize_encode(fi->done, buf);
			g_assert(len > 0 && UNSIGNED(len) <= sizeof buf);
			ok = ok && ggep_stream_pack(&gs, GGEP_NAME(avail), buf, len, 0);
		}
	}

	{
		char buf[sizeof(guint16)];
		guint16 port = socket_listen_port();

		poke_be16(buf, port);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(port), buf, sizeof buf, 0);
	}

	if (tls_enabled()) {
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(tls), NULL, 0, 0);
	}

	tth = shared_file_tth(sf);
	if (tth != NULL) {
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(ttroot),
			tth->data, sizeof tth->data, 0);
	}

	if (
		!GNET_PROPERTY(is_firewalled) &&
		GNET_PROPERTY(give_server_hostname) &&
		!is_null_or_empty(GNET_PROPERTY(server_hostname))
	) {
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(HNAME),
			GNET_PROPERTY(server_hostname),
			strlen(GNET_PROPERTY(server_hostname)), 0);
	}

	ggep_len = ggep_stream_close(&gs);

	g_assert(ggep_len <= DHT_VALUE_MAX_LEN);

	if (!ok) {
		if (GNET_PROPERTY(publisher_debug)) {
			g_warning("PDHT ALOC cannot construct DHT value for %s \"%s\"",
				shared_file_is_partial(sf) ? "partial" : "shared",
				shared_file_name_nfc(sf));
		}

		wfree(value, DHT_VALUE_MAX_LEN);
		return NULL;
	}

	/*
	 * DHT value becomes the owner of the walloc()-ed GGEP block.
	 */

	g_assert(ggep_len > 0);

	value = wrealloc(value, DHT_VALUE_MAX_LEN, ggep_len);
	our_knode = get_our_knode();
	aloc = dht_value_make(our_knode, key, DHT_VT_ALOC,
		PDHT_ALOC_MAJOR, PDHT_ALOC_MINOR, value, ggep_len);
	knode_refcnt_dec(our_knode);

	return aloc;
}

/**
 * Callback when lookup for STORE roots succeeded for ALOC publishing.
 */
static void
pdht_aloc_roots_found(const kuid_t *kuid, const lookup_rs_t *rs, gpointer arg)
{
	pdht_publish_t *pp = arg;
	struct pdht_aloc *paloc = &pp->u.aloc;
	shared_file_t *sf;
	dht_value_t *value;

	pdht_publish_check(pp);
	g_assert(pp->id == kuid);		/* They are atoms */

	sf = paloc->sf;

	if (GNET_PROPERTY(publisher_debug) > 1) {
		size_t roots = lookup_result_path_length(rs);
		g_message("PDHT ALOC found %lu publish root%s for %s \"%s\"",
			(unsigned long) roots, 1 == roots ? "" : "s",
			shared_file_is_partial(sf) ? "partial" : "shared",
			shared_file_name_nfc(sf));
	}

	/*
	 * Step #2: if file is still publishable, generate the DHT ALOC value
	 *
	 * If shared_file_by_sha1() returns SHARE_REBUILDING, we nonetheless
	 * go on with the publishing because chances are the file will still
	 * be shared anyway.  If no longer shared, it will not be requeued for
	 * publishing at the next period.
	 */

	if (NULL == shared_file_by_sha1(paloc->sha1)) {
		if (GNET_PROPERTY(publisher_debug)) {
			g_warning("PDHT ALOC cannot publish %s \"%s\": no longer shared",
				shared_file_is_partial(sf) ? "partial" : "shared",
				shared_file_name_nfc(sf));
		}

		pdht_publish_error(pp, PDHT_E_NOT_SHARED);
		return;
	}

	value = pdht_get_aloc(sf, pp->id);

	if (NULL == value) {
		pdht_publish_error(pp, PDHT_E_GGEP);
		return;
	}

	g_assert(kuid_eq(dht_value_key(value), pp->id));

	/*
	 * Step #3: issue the STORE on each of the k identified nodes.
	 */

	pp->value = dht_value_clone(value);
	pp->pb = publish_value(value, rs, pdht_publish_done, pp);
}

/**
 * Callback for errors during ALOC publishing.
 */
static void
pdht_aloc_roots_error(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	pdht_publish_t *pp = arg;
	struct pdht_aloc *paloc = &pp->u.aloc;
	pdht_error_t status;

	pdht_publish_check(pp);
	g_assert(pp->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(publisher_debug)) {
		g_message("PDHT ALOC publish roots lookup failed for %s \"%s\": %s",
			shared_file_is_partial(paloc->sf) ? "partial" : "shared",
			shared_file_name_nfc(paloc->sf), lookup_strerror(error));
	}

	switch (error) {
	case LOOKUP_E_UDP_CLOGGED:		status = PDHT_E_UDP_CLOGGED; break;
	case LOOKUP_E_EXPIRED:			status = PDHT_E_PUBLISH_EXPIRED; break;
	default:						status = PDHT_E_LOOKUP; break;
	}

	pdht_publish_error(pp, status);
}

/**
 * Asynchronous error reporting context.
 */
struct pdht_async {
	pdht_publish_t *pp;
	pdht_error_t code;
};

/**
 * Callout queue callback to report error asynchronously.
 */
static void
pdht_report_async_error(struct cqueue *cq, gpointer udata)
{
	struct pdht_async *pa = udata;

	(void) cq;
	pdht_publish_error(pa->pp, pa->code);
	wfree(pa, sizeof *pa);
}

/**
 * Asynchronously report error.
 */
static void
pdht_publish_error_async(pdht_publish_t *pp, pdht_error_t code)
{
	struct pdht_async *pa;

	pa = walloc(sizeof *pa);
	pa->pp = pp;
	pa->code = code;

	cq_insert(callout_queue, 1, pdht_report_async_error, pa);
}

/**
 * Launch publishing of shared file within the DHT.
 *
 * @param sf		the shared file to publish
 * @param cb		callback to invoke when publish is completed
 * @param arg		argument to supply to callback
 */
void
pdht_publish_file(shared_file_t *sf, pdht_cb_t cb, gpointer arg)
{
	const char *error = NULL;
	const sha1_t *sha1;
	pdht_publish_t *pp;
	struct pdht_aloc *paloc;
	pdht_error_t code;

	g_assert(sf != NULL);

	pp = walloc0(sizeof *pp);
	pp->magic = PDHT_PUBLISH_MAGIC;
	pp->type = PDHT_T_ALOC;
	pp->cb = cb;
	pp->arg = arg;
	paloc = &pp->u.aloc;
	paloc->sf = shared_file_ref(sf);

	if (!sha1_hash_available(sf) || !sha1_hash_is_uptodate(sf)) {
		error = "no SHA1 available";
		code = PDHT_E_SHA1;
		goto error;
	}

	sha1 = shared_file_sha1(sf);
	g_assert(sha1 != NULL);

	pp->id = gdht_kuid_from_sha1(sha1);
	paloc->sha1 = atom_sha1_get(sha1);

	if (g_hash_table_lookup(aloc_publishes, sha1)) {
		error = "previous publish still pending";
		code = PDHT_E_PENDING;
		goto error;
	}

	gm_hash_table_insert_const(aloc_publishes, paloc->sha1, pp);

	/*
	 * Publishing will occur in three steps:
	 *
	 * #1 locate suitable nodes for publishing the ALOC value
	 * #2 if file is still publishable, generate the DHT ALOC value
	 * #3 issue the STORE on each of the k identified nodes.
	 *
	 * Here we launch step #1.
	 */

	ulq_find_store_roots(pp->id,
		pdht_aloc_roots_found, pdht_aloc_roots_error, pp);

	return;

error:
	if (GNET_PROPERTY(publisher_debug)) {
		g_warning("PDHT will not publish ALOC for %s \"%s\": %s",
			shared_file_is_partial(sf) ? "partial" : "shared",
			shared_file_name_nfc(sf), error);
	}

	/*
	 * Report error asynchronously, to return to caller first.
	 */

	pdht_publish_error_async(pp, code);
}

/**
 * Cancel a file publishing.
 *
 * @param sha1		the SHA1 of the file
 * @param callabck	whether callbacks need to be invoked
 */
void
pdht_cancel_file(const sha1_t *sha1, gboolean callback)
{
	pdht_publish_t *pp;

	pp = g_hash_table_lookup(aloc_publishes, sha1);

	if (NULL == pp)
		return;

	pdht_publish_check(pp);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		shared_file_t *sf = pp->u.aloc.sf;
		g_warning("PDHT cancelling ALOC for %s \"%s\" (%s callback): %s",
			shared_file_is_partial(sf) ? "partial" : "shared",
			shared_file_name_nfc(sf),
			callback ? "with" : "no", sha1_to_string(sha1));
	}

	/*
	 * By setting PDHT_F_CANCELLING we avoid the publish callback from
	 * freeing the publishing object, since we are going to do that
	 * ourselves once we return from the publish_cancel() call.
	 */

	pp->flags |= PDHT_F_CANCELLING;

	if (pp->pb != NULL) {
		publish_cancel(pp->pb, callback);
		pp->pb = NULL;
	}

	pdht_free_publish(pp, TRUE);
}

/**
 * Initialize the Gnutella DHT layer.
 */
void
pdht_init(void)
{
	aloc_publishes = g_hash_table_new(sha1_hash, sha1_eq);
}

/**
 * Hash table iterator to free a pdht_publish_t
 */
static void
free_publish_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	pdht_publish_t *pp = val;

	(void) unused_key;
	(void) unused_x;

	pdht_free_publish(pp, FALSE);
}

/**
 * Shutdown the Gnutella DHT layer.
 */
void
pdht_close(void)
{
	g_hash_table_foreach(aloc_publishes, free_publish_kv, NULL);
	g_hash_table_destroy(aloc_publishes);
	aloc_publishes = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
