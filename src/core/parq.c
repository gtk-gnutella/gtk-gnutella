/*
 * $Id$
 *
 * Copyright (c) 2003 - 2004, Raphael Manfredi
 * Copyright (c) 2003 - 2005, Jeroen Asselman
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
 * Passive/Active Remote Queuing.
 *
 * @author Jeroen Asselman
 * @author Raphael Manfredi
 * @date 2003-2005
 */

#include "common.h"

RCSID("$Id$")

#include "parq.h"
#include "ban.h"
#include "downloads.h"
#include "dmesh.h"
#include "features.h"
#include "guid.h"
#include "http.h"
#include "ioheader.h"
#include "settings.h"
#include "share.h"
#include "sockets.h"
#include "gnet_stats.h"
#include "hosts.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/bit_array.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"			/* Must be the last header included */

#define PARQ_VERSION_MAJOR	1
#define PARQ_VERSION_MINOR	0

#define PARQ_RETRY_SAFETY	40		/**< 40 seconds before lifetime */
#define PARQ_TIMER_BY_POS	30		/**< 30 seconds for each queue position */
#define GUARDING_TIME		45		/**< Time we keep a slot after disconnect */
#define MIN_LIFE_TIME		90
#define QUEUE_PERIOD		600		/**< Try to resend a queue every 10 min. */
#define MAX_QUEUE			144		/**< Max amount of QUEUE we can send */
#define MAX_QUEUE_REFUSED	2		/**< Max QUEUE they can refuse in a row */

#define MAX_UPLOADS			100		/**< Avoid more than that many uploads */
#define MAX_UPLOAD_QSIZE	4000	/**< Size of the PARQ queue */

#define MEBI (1024 * 1024)
/*
 * File sizes in queues:
 *
 * 1 ul: 0 < q1 < oo
 * 2 ul: 0 < q2 <= 300 Mi < q1 < oo
 * 3 ul: 0 < q3 <= 150 Mi < q2 <= 300 Mi < q1 < oo
 * ...
 */
#define PARQ_UL_LARGE_SIZE (300 * MEBI)

#define PARQ_UL_MAGIC	0x6a3900a1

static GHashTable *dl_all_parq_by_id = NULL;

static guint parq_max_upload_size = MAX_UPLOAD_QSIZE;


/**
 * parq_upload_active_size is the maximum number of active upload slots
 * per queue.
 *
 * This limit will only be reached when all requests are QUEUE, push or
 * the number of upload slots is also large.
 */
static guint parq_upload_active_size = 20;

static guint parq_upload_ban_window = 600;
static const gchar file_parq_file[] = "parq";

static GList *ul_parqs = NULL;			/**< List of all queued uploads */
static GList *ul_parq_queue = NULL;		/**< To whom we need to send a QUEUE */
static GHashTable *ul_all_parq_by_addr_and_name = NULL;
static GHashTable *ul_all_parq_by_addr = NULL;
static GHashTable *ul_all_parq_by_id = NULL;

/**
 * If enable_real_passive is TRUE, a dead upload is only marked dead,
 * if FALZE, a dead upload is really removed and cannot reclaim its
 * position
 */
static gboolean enable_real_passive = TRUE;


static GHashTable *ht_banned_source = NULL;
static GList *parq_banned_sources = NULL;

struct parq_banned {
	host_addr_t addr;
	time_t added;
	time_t expire;
};


static gboolean parq_shutdown = FALSE;

/**
 * Holds status of current queue.
 */
struct parq_ul_queue {
	GList *by_position;		/**< Queued items sorted on position. Newest is
								 added to the end. */
	GList *by_rel_pos;		/**< Queued items sorted by relative position */
	GList *by_date_dead;	/**< Queued items sorted on last update and
								 not alive */
	gint size;				/**< Number of entries in current list */

	gboolean active;		/**< Set to false when the number of upload slots
								 was decreased but the queue still contained
								 queued items. This queue shall be removed when
								 all queued items are finished / removed. */
	gint active_uploads;
	gint alive;
};

struct parq_ul_queued_by_addr {
	gint	uploading;		/**< Number of uploads uploading */
	gint	total;			/**< Total queued items for this ip */
	gint 	active_queued;	/**< Total actively queued items for this ip */
	host_addr_t addr;

	time_t	last_queue_sent;
	time_t	last_queue_connected;

	GList	*list;			/**< List or queued items for this ip */
};

/**
 * Contains the queued upload.
 */
struct parq_ul_queued {
	guint32 magic;			/**< Magic number */
	guint32 flags;			/**< Operating flags */
	guint position;			/**< Current position in the queue */
	guint relative_position; /**< Relative position in the queue, if 'not alive'
								  uploads are taken into account */
	gboolean quick;			/**< Slot granted for allowed quick upload */
	gboolean active_queued;	/**< Whether the current upload is actively queued */
	gboolean has_slot;		/**< Whether the items is currently uploading */
	gboolean had_slot;		/**< If an upload had an upload slot it is not
							     allowed to reuse the id for another upload	*/
	guint eta;				/**< Expected time in seconds till an upload slot is
							     reached, this is a relative timestamp */

	time_t expire;			/**< Time when the queue position will be lost */
	time_t retry;			/**< Time when the first retry-after is expected */
	time_t enter;			/**< Time upload entered parq */
	time_t updated;			/**< Time last upload request was sent */
	time_t ban_timeout;		/**< Time after which we won't kick out the upload
							     out of the queue when retry isn't obeyed */
	time_t disc_timeout;	/**< Time after which we allow the upload to be
							     disconnected again. */
	guint ban_countwait;	/**< Counter is increased everytime a client did
								 not obey the retry-after header, used to
								 ban a client. */

	time_t last_queue_sent;	/**< When we last sent the QUEUE */
	time_t send_next_queue; /**< When will we send the next QUEUE */

	guint32 queue_sent;		/**< Amount of QUEUE messages we tried to send */
	guint32 queue_refused;	/**< Amount of QUEUE messages refused remotely */

	gboolean is_alive;		/**< Whether client is still requesting this file */

	gchar id[GUID_RAW_SIZE];		/**< PARQ identifier; GUID atom */

	gchar *addr_and_name;	/**< "IP name", used as key in hash table */
	const gchar *name;		/**< NB: points directly into `addr_and_name' */
	const gchar *sha1;		/**< SHA1 digest for easy reference */
	host_addr_t remote_addr;		/**< IP address of the socket endpoint */

	filesize_t file_size;	/**< Needed to recalculate ETA */
	filesize_t chunk_size;	/**< Requested chunk size */
	filesize_t uploaded_size;	/**< Bytes previously uploaded */
	host_addr_t addr;		/**< Contact IP:port, as read from X-Node: */
	guint16 port;

	guint major;
	guint minor;

	struct parq_ul_queue *queue;	/**< In which queue this entry is listed */
	struct parq_ul_queued_by_addr *by_addr;

	gnutella_upload_t *u;	/**< Internal reference to upload structure if
							     available */
};

/*
 * Flags for parq_ul_queued.
 */

#define PARQ_UL_QUEUE		0x00000001	/**< Scheduled for QUEUE sending */
#define PARQ_UL_NOQUEUE		0x00000002	/**< No IP:port, don't send QUEUE */
#define PARQ_UL_QUEUE_SENT	0x00000004	/**< QUEUE message sent */
#define PARQ_UL_ID_SENT		0x00000008	/**< We already sent an ID */

/**
 * Contains the queued download status.
 */
struct parq_dl_queued {
	guint position;			/**< Current position in the queue */
	guint length;			/**< Current queue length */
	time_t eta;				/**< Estimated time till upload slot retrieved */
	guint lifetime;			/**< Max interval before loosing queue position */
	guint retry_delay;		/**< Interval between new attempt */
	gchar *id;				/**< PARQ Queue ID, +1 for trailing NUL */
};


void parq_dl_del_id(struct download *d);

static void parq_upload_free(struct parq_ul_queued *parq_ul);
static struct parq_ul_queued *parq_upload_create(gnutella_upload_t *u);
static struct parq_ul_queue *parq_upload_which_queue(gnutella_upload_t *u);
static struct parq_ul_queue *parq_upload_new_queue();
static void parq_upload_free_queue(struct parq_ul_queue *queue);
static void parq_upload_update_eta(struct parq_ul_queue *which_ul_queue);
static struct parq_ul_queued *parq_upload_find(const gnutella_upload_t *u);
static gint parq_ul_rel_pos_cmp(gconstpointer a, gconstpointer b);
static gboolean parq_upload_continue(
		struct parq_ul_queued *uq, gint free_slots);
static void parq_upload_decrease_all_after(struct parq_ul_queued *cur_parq_ul);
static void parq_upload_load_queue();
static void parq_upload_update_relative_position(
		struct parq_ul_queued *parq_ul);
static void parq_upload_update_addr_and_name(struct parq_ul_queued *parq_ul,
	gnutella_upload_t *u);

static void parq_upload_register_send_queue(struct parq_ul_queued *parq_ul);
static void parq_upload_send_queue(struct parq_ul_queued *parq_ul);

static gboolean parq_still_sharing(struct parq_ul_queued *);

void parq_add_banned_source(const host_addr_t addr, time_t delay);
void parq_del_banned_source(const host_addr_t addr);

/***
 ***  Generic non PARQ specific functions
 ***/

/**
 * Get header version.
 *
 * Extract the version from a given header. EG:
 * X-Queue: 1.0
 * major=1 minor=0
 *
 * @param header is a pointer to the header string that will be parsed for
 *        the version number
 * @param major is a pointer to a gint in which the major version number will
 *        be returned on success.
 * @param minor is a pointer to a gint in which the minor version number will
 *        be returned on success.
 *
 * @return a boolean which is true when parsing of the header version was
 * successful.
 */
static gboolean
get_header_version(gchar const * const header, guint *major, guint *minor)
{
	return 0 == parse_major_minor(header, NULL, major, minor);
}

/**
 * Get header value.
 *
 * Retrieves a value from a header line. If possible the length (in gchars)
 * is returned for that value.
 *
 * @param s is a pointer to the header string that will be parsed.
 * @param attribute is the attribute which will be searched in the header string
 * @param length is a pointer to a size_t variable which will contain the
 *		  length of the header value, if parsing was successful.
 *
 * @return a pointer in the s pointer indicating the start of the header value.
 */
static gchar *
get_header_value(gchar *const s, gchar const *const attribute, size_t *length)
{
	gchar *header = s;
	gchar *end;
	gboolean found_right_attribute = FALSE;
	gboolean found_equal_sign = FALSE;

	size_t attrlen;

	g_assert(s != NULL);
	g_assert(attribute != NULL);

	attrlen = strlen(attribute);

	/*
	 * When we are looking for "foo", make sure we aren't actually
	 * parsing "barfoobar". There should be at least a space, or a
	 * delimiter at the end and at the beginning.
	 */

	do {
		gchar e;
		gchar b;
		gchar es;

		header = ascii_strcasestr(header, attribute);

		if (header == NULL)
			return NULL;

		e = header[attrlen];		/* End char after attribute */

		if (header == s) {
			/*
			 * This is actually the first value of the header. And it
			 * started at position '0'. Which is the same as were
			 * s pointed too. Only check to see if the end is correct
			 */

			found_right_attribute = e == ' ' || e == '=' || e == '\0';
		} else {
			b = *(header - 1);	/* Character before attribute */
			found_right_attribute = (
					b == ';' || b == ',' || b == ':' || b == ' '
				) && (
					e == ' ' || e == '=' || e == '\0'
				);
		}

		/*
		 * If we weren't looking at the right value. Move on to the next.
		 * If there are no valid values, the while loop will abort with
		 * lowercase_header == NULL
		 * If we did find a valid position we want to make sure the next
		 * char is an '='. So we need to move ahead anyway.
		 */

		header += attrlen;

		if (found_right_attribute) {

			/*
			 * OK, so we found a possible valid attribute. Now make sure the
			 * first character is an '=', ignoring white spaces.
			 * If we don't, we didn't find a valid attribute.
			 */

			es = *header;

			do {
				found_right_attribute = es == '=' || es == ' ' || es == '\0';
				found_equal_sign = es == '=';

				if (!found_equal_sign)
					es = *(++header);		/* Skip spaces */

			} while (!found_equal_sign && found_right_attribute && es != '\0');

			/*
			 * If we did not find the right attribute, it means we did not
			 * encounter an '=' sign before the start of the next attribute
			 * or the end of the string.
			 *
			 * For instance, we stumbled on `var2' in:
			 *
			 *   var1 = foo; var2 ; var3=bar
			 *
			 * Clearly, this is incorrect for our purposes, as all attributes
			 * are expected to have a value.
			 */

			g_assert(!found_equal_sign || found_right_attribute);

			if (!found_right_attribute) {
				g_assert(!found_equal_sign);
				g_warning("%s: attribute '%s' has no value in string: %s",
					__FILE__, attribute, s);
			}
		}
	} while (!found_right_attribute);

	g_assert(header != NULL);
	g_assert(found_equal_sign);
	g_assert(*header == '=');

	header++;			/* Skip the '=' sign */

	/*
	 * If we need to compute the length of the attribute's value, look for
	 * the next trailing delimiter (';' or ',').
	 */

	if (length != NULL) {
		*length = 0;

		end = strchr(header, ';');		/* PARQ style */
		if (end == NULL)
			end = strchr(header, ',');	/* Active queuing style */

		/*
		 * If we couldn't find a delimiter, then this value is the last one.
		 */

		*length = (end == NULL) ? strlen(header) : (size_t) (end - header);
	}

	return header;
}


/***
 ***  The following section contains download PARQ functions
 ***/

/**
 * Retrieves the PARQ ID associated with an download.
 *
 * @return a gchar pointer to the ID, or NULL if no ID is available.
 */
const gchar *
get_parq_dl_id(const struct download *d)
{
	const struct parq_dl_queued *q;

	g_assert(d != NULL);

	q = d->queue_status;
	return q ? q->id : NULL;
}

/**
 * Retrieves the remote queued position associated with an download.
 *
 * @returns the remote queued position or 0 if download is not queued or
 * queuing status is unknown
 */
gint
get_parq_dl_position(const struct download *d)
{
	g_assert(d != NULL);

	if (d->queue_status == NULL)
		return 0;

	return ((struct parq_dl_queued *) d->queue_status)->position;
}

/**
 * Retrieves the remote queue size associated with an download.
 *
 * @return the remote queue size or 0 if download is not queued or queueing
 * status is unknown.
 */
gint
get_parq_dl_queue_length(const struct download *d)
{
	g_assert(d != NULL);

	if (d->queue_status == NULL)
		return 0;

	return ((struct parq_dl_queued *) d->queue_status)->length;
}

/**
 * Retrieves the estimated time of arival for a queued download.
 *
 * @return the relative eta or 0 if download is not queued or queuing status is
 * unknown.
 */
gint
get_parq_dl_eta(const struct download *d)
{
	g_assert(d != NULL);

	if (d->queue_status == NULL)
		return 0;

	return ((struct parq_dl_queued *) d->queue_status)->eta;
}

/**
 * Retrieves the retry rate at which a queued download should retry.
 *
 * @return the retry rate or 0 if download is not queued or queueing status is
 * unknown.
 */
gint
get_parq_dl_retry_delay(const struct download *d)
{
	g_assert(d != NULL);

	if (d->queue_status == NULL)
		return 0;

	return ((struct parq_dl_queued *) d->queue_status)->retry_delay;
}

/**
 * Active queued means we didn't close the http connection on a HTTP 503 busy
 * when the server supports queueing. So prepare the download structure
 * for a 'valid' segment. And re-request the segment.
 */
void
parq_download_retry_active_queued(struct download *d)
{
	g_assert(d != NULL);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_ACTIVE_QUEUED);
	g_assert(d->queue_status != NULL);
	g_assert(parq_download_is_active_queued(d));

	if (download_start_prepare_running(d)) {
		struct gnutella_socket *s = d->socket;
		d->keep_alive = TRUE;			/* was reset in start_prepare_running */

 		/* Will be re initialised in download_send_request */
		io_free(d->io_opaque);
		d->io_opaque = NULL;
		getline_free(s->getline);		/* No longer need this */
		s->getline = NULL;

		/* Resend request for download */
		download_send_request(d);
	}
}

/**
 * Convenience wrapper on top of parse_uint32().
 *
 * @return parsed integer (base 10), or 0 if none could be found.
 */
static guint
get_integer(const gchar *buf)
{
	const gchar *endptr;
	guint32 val;
	gint error;

	/* XXX This needs to get more parameters, so that we can log the
	 * XXX problem if we cannot parse, or if the value does not fit.
	 * XXX We probably need the download structure, and the name of
	 * XXX the field being parsed, with the header line as well.
	 * XXX	--RAM, 02/02/2003.
	 */

	buf = skip_ascii_spaces(buf);
	val = parse_uint32(buf, &endptr, 10, &error);
	if (endptr == buf)
		return 0;

	return error || val > INT_MAX ? INT_MAX : val;
}

/**
 * Tells the parq logic that a download has been removed. If parq has
 * associated a queue structure with this download it will be freed.
 */
void
parq_dl_remove(struct download *d)
{
	if (d->queue_status != NULL)
		parq_dl_free(d);
}

/**
 * Removes the queue information for a download from memory.
 */
void
parq_dl_free(struct download *d)
{
	struct parq_dl_queued* parq_dl = NULL;

	parq_dl = (struct parq_dl_queued *) d->queue_status;

	if (parq_dl->id != NULL)
		parq_dl_del_id(d);

	g_assert(parq_dl->id == NULL);

	wfree(parq_dl, sizeof(struct parq_dl_queued));

	parq_dl = NULL;
	d->queue_status = NULL;

	g_assert(d->queue_status == NULL);
}

/**
 * Creates a queue structure for a download.
 *
 * @return a parq_dl_queued pointer to the newly created structure.
 */
gpointer
parq_dl_create(struct download *d)
{
	struct parq_dl_queued* parq_dl = NULL;

	g_assert(d->queue_status == NULL);

	parq_dl = walloc(sizeof(*parq_dl));

	parq_dl->id = NULL;		/* Can't allocate yet, ID size isn't fixed */
	parq_dl->position = 0;

	return parq_dl;
}

/**
 * Assigns an parq ID to a download, and places them in various lists for lookup
 */
void
parq_dl_add_id(struct download *d, const gchar *new_id)
{
	struct parq_dl_queued *parq_dl = NULL;

	g_assert(d != NULL);
	g_assert(new_id != NULL);
	g_assert(d->queue_status != NULL);

	parq_dl = d->queue_status;

	g_assert(parq_dl != NULL);
	g_assert(parq_dl->id == NULL);	/* We don't expect an id here */

	parq_dl->id = g_strdup(new_id);
	g_hash_table_insert(dl_all_parq_by_id, parq_dl->id, d);

	g_assert(parq_dl->id != NULL);
}

/**
 * Remove the memory used by the ID string, and removes it from
 * various lists
 */
void
parq_dl_del_id(struct download *d)
{
	struct parq_dl_queued *parq_dl = NULL;

	g_assert(d != NULL);

	parq_dl = (struct parq_dl_queued *) d->queue_status;

	g_assert(parq_dl != NULL);
	g_assert(parq_dl->id != NULL);

	g_hash_table_remove(dl_all_parq_by_id, parq_dl->id);
	G_FREE_NULL(parq_dl->id);

	g_assert(parq_dl->id == NULL);	/* We don't expect an id here */
}

/**
 * Called from download_clone to reparent the PARQ ID from the parent `d'
 * to the cloned `cd'.
 */
void
parq_dl_reparent_id(struct download *d, struct download *cd)
{
	struct parq_dl_queued *parq_dl = NULL;

	g_assert(d != NULL);
	g_assert(cd != NULL);

	parq_dl = (struct parq_dl_queued *) d->queue_status;

	g_assert(parq_dl != NULL);
	g_assert(d->queue_status == cd->queue_status);	/* Cloned */

	/*
	 * Legacy queueing might not provide any ID.
	 */

	if (parq_dl->id != NULL) {
		g_hash_table_remove(dl_all_parq_by_id, parq_dl->id);
		g_hash_table_insert(dl_all_parq_by_id, parq_dl->id, cd);
	}

	d->queue_status = NULL;			/* No longer associated to `d' */
}

/**
 * Updates a parq id if needed.
 */
static void
parq_dl_update_id(struct download *d, const gchar *temp)
{
	struct parq_dl_queued *parq_dl = NULL;

	g_assert(d != NULL);
	g_assert(temp != NULL);

	parq_dl = d->queue_status;
	if (parq_dl->id != NULL) {
		if (0 == strcmp(temp, parq_dl->id))
			return;

		parq_dl_del_id(d);
	}

	parq_dl_add_id(d, temp);
}

/**
 * Retrieve and parse queueing information.
 *
 * @return TRUE if we parsed it OK, FALSE on error.
 */
gboolean
parq_download_parse_queue_status(struct download *d, header_t *header)
{
	struct parq_dl_queued *parq_dl = NULL;
	gchar *buf = NULL;
	gchar *temp = NULL;
	gchar *value = NULL;
	guint major = 0, minor = 0;
	size_t header_value_length;
	gint retry;

	g_assert(d != NULL);
	g_assert(header != NULL);

	buf = header_get(header, "X-Queue");

	if (buf == NULL)			/* Remote server does not support queues */
		return FALSE;

	header_get_feature("queue", header, &major, &minor);

	if (major == 0 && minor == 0 && !get_header_version(buf, &major, &minor)) {
		/*
	 	* Could not retrieve queueing version. It could be 0.1 but there is
		* no way to tell for certain
	 	*/
		major = 0;
		minor = 1;
	}

	d->server->parq_version.major = major;
	d->server->parq_version.minor = minor;

	if (d->queue_status == NULL) {
		/* So this download has no parq structure yet, well create one! */
		d->queue_status = parq_dl_create(d);
	}

	parq_dl = (struct parq_dl_queued *) d->queue_status;

	g_assert(parq_dl != NULL);

	switch (major) {
	case 0:				/* Active queueing */
		g_assert(buf != NULL);
		value = get_header_value(buf, "pollMin", NULL);
		parq_dl->retry_delay  = value == NULL ? 0 : get_integer(value);

		value = get_header_value(buf, "pollMax", NULL);
		parq_dl->lifetime  = value == NULL ? 0 : get_integer(value);
		break;
	case 1:				/* PARQ */
		buf = header_get(header, "X-Queued");

		if (buf == NULL) {
			g_warning("[PARQ DL] host %s advertised PARQ %d.%d but did not"
				" send X-Queued",
				host_addr_port_to_string(download_addr(d), download_port(d)),
				major, minor);
			if (parq_debug) {
				g_warning("[PARQ DL]: header dump:");
				header_dump(header, stderr);
			}
			return FALSE;
		}

		parq_dl->retry_delay = extract_retry_after(d, header);

		value = get_header_value(buf, "lifetime", NULL);
		parq_dl->lifetime = value == NULL ?
			parq_dl->retry_delay + 1 : get_integer(value);

		/* Someone might not be playing nicely. */
		if (parq_dl->lifetime < parq_dl->retry_delay) {
			parq_dl->lifetime = MAX(300, parq_dl->retry_delay );
			g_warning("[PARQ DL] Invalid lifetime, using: %d",
				  parq_dl->lifetime);
		}

		value = get_header_value(buf, "ID", &header_value_length);
		if (header_value_length > 0) {
			temp = g_strndup(value, header_value_length);

			parq_dl_update_id(d, temp);

			G_FREE_NULL(temp);
		}
		break;
	default:
		g_warning("[PARQ DL] unhandled queuing version %d.%d from %s <%s>",
			major, minor, host_addr_port_to_string(download_addr(d), download_port(d)),
			download_vendor_str(d));
		return FALSE;
	}

	value = get_header_value(buf, "position", NULL);
	parq_dl->position = value == NULL ? 0 : get_integer(value);

	value = get_header_value(buf, "length", NULL);
	parq_dl->length   = value == NULL ? 0 : get_integer(value);

	value = get_header_value(buf, "ETA", NULL);
	parq_dl->eta  = value == NULL ? 0 : get_integer(value);

	/*
	 * If we're not in the first position, lower our retry rate.
	 * We try to retry every 60 seconds when in position 2, every 90 in
	 * position 3, and so on.  If we fall out of range, adjust: we must not
	 * poll before the minimum specified by `retry_delay', and we try to
	 * poll again at least 40 seconds before `lifetime' to avoid being
	 * kicked out.
	 *		--RAM, 22/02/2003
	 */

	retry = parq_dl->position * PARQ_TIMER_BY_POS;

	if (retry > (gint) (parq_dl->lifetime - PARQ_RETRY_SAFETY))
		retry = parq_dl->lifetime - PARQ_RETRY_SAFETY;
	if (retry < (gint) parq_dl->retry_delay)
		retry = parq_dl->retry_delay;

	if (parq_debug > 2)
		g_message("Queue version: %d.%d, position %d out of %d,"
			" retry in %ds within [%d, %d]",
			major, minor, parq_dl->position, parq_dl->length,
			retry, parq_dl->retry_delay, parq_dl->lifetime);

	if (parq_download_is_active_queued(d)) {
		/*
		 * Don't keep a chunk busy if we are queued, perhaps another servent
		 * can complete it for us.
		 */

		file_info_clear_download(d, TRUE);
		download_actively_queued(d, TRUE);
	}

	d->timeout_delay = retry;

	return TRUE;		/* OK */
}

/**
 * Whether the download is queued remotely or not.
 */
gboolean
parq_download_is_active_queued(struct download *d)
{
	struct parq_dl_queued *parq_dl;

	g_assert(d != NULL);
	parq_dl = d->queue_status;
	if (parq_dl == NULL)
		return FALSE;

	return parq_dl->position > 0 && d->keep_alive;
}

/**
 * Whether the download is queued remotely without keeping the connection or not
 */
gboolean
parq_download_is_passive_queued(struct download *d)
{
	struct parq_dl_queued *parq_dl;

	g_assert(d != NULL);

	parq_dl = d->queue_status;

	if (parq_dl == NULL)
		return FALSE;

	return parq_dl->position > 0 && !d->keep_alive;
}


/**
 * Needs brief description here.
 *
 * Adds an:
 *
 *    - X-Queue: 1.0
 *    - X-Queued: position=x; ID=xxxxx
 *
 * to the HTTP GET request.
 */
void
parq_download_add_header(
	gchar *buf, size_t len, size_t *rw, struct download *d)
{
	gint major = PARQ_VERSION_MAJOR;
	gint minor = PARQ_VERSION_MINOR;

	g_assert(d != NULL);
	g_assert(rw != NULL);
	g_assert((int) len >= 0 && len <= INT_MAX);
	g_assert((int) *rw >= 0 && *rw <= INT_MAX);
	g_assert(len >= *rw);

	*rw += gm_snprintf(&buf[*rw], len - *rw,
		"X-Queue: %d.%d\r\n", major, minor);

	/*
	 * Only add X-Queued header if server really supports X-Queue: 1.x. Don't
	 * add X-Queued if there is no ID available. This could be because it is
	 * a first request.
	 */

	if (d->server->parq_version.major == 1) {
		if (get_parq_dl_id(d) != NULL)
			*rw += gm_snprintf(&buf[*rw], len - *rw,
				  	"X-Queued: position=%d; ID=%s\r\n",
				  	get_parq_dl_position(d),
				  	get_parq_dl_id(d));
	}

	/*
	 * Only send X-Node if not firewalled and the listen IP/port combination
	 * we're claiming is "valid".
	 */

	if (!is_firewalled && host_is_valid(listen_addr(), socket_listen_port()))
		*rw += gm_snprintf(&buf[*rw], len - *rw,
		  	  "X-Node: %s\r\n",
			  host_addr_port_to_string(listen_addr(), socket_listen_port()));
}

/**
 * parq_download_queue_ack
 *
 * PARQ enabled servers send a 'QUEUE' command when the lifetime of the download
 * (upload from the servers point of view) is about to expire, or if the
 * download has retrieved an download slot (upload slot from the servers point
 * of view). This function looksup the ID associated with the QUEUE command
 * and prepares the download to continue.
 */
void
parq_download_queue_ack(struct gnutella_socket *s)
{
	const gchar *queue;
	gchar *id;
	gchar *ip_str;
	struct download *dl;
	host_addr_t addr;
	guint16 port = 0;
	gboolean has_ip_port = TRUE;

	socket_tos_default(s);	/* Set proper Type of Service */

	g_assert(s != NULL);
	g_assert(s->getline);

	queue = getline_str(s->getline);

	gnet_stats_count_general(GNR_QUEUE_CALLBACKS, 1);

	if (parq_debug > 2 || download_debug > 2) {
		g_message("--- Got QUEUE from %s:\n%s\n---",
			host_addr_to_string(s->addr), queue);
	}

	id = is_strprefix(queue, "QUEUE ");
 	/* ensured by socket_read() */
	g_assert(id != NULL);
	id = skip_ascii_spaces(id);

	/*
	 * Fetch the IP port at the end of the QUEUE string.
	 */

	ip_str = strchr(id, ' ');

	if (
		ip_str == NULL ||
		!string_to_host_addr_port(&ip_str[1], NULL, &addr, &port)
	) {
		g_warning("[PARQ DL] missing IP:port in \"%s\" from %s",
			queue, host_addr_to_string(s->addr));
		has_ip_port = FALSE;
	}

	/*
	 * Terminate the ID part from the QUEUE message.
	 */

	if (ip_str != NULL)
		*ip_str = '\0';

	dl = g_hash_table_lookup(dl_all_parq_by_id, id);

	/*
	 * If we were unable to locate a download by this ID, try to elect
	 * another download from this host for which we don't have any PARQ
	 * information yet.
	 */

	if (dl == NULL) {
        if (parq_debug) {
            g_message("[PARQ DL] could not locate QUEUE id '%s' from %s",
                id, host_addr_port_to_string(addr, port));
        }

		if (has_ip_port) {
			dl = download_find_waiting_unparq(addr, port);

			if (dl != NULL) {
                if (parq_debug) {
                    g_message("[PARQ DL] elected '%s' from %s for QUEUE"
                        " id '%s'",
                        dl->file_name,
						host_addr_port_to_string(addr, port), id);
                }

				g_assert(dl->queue_status == NULL);		/* unparq'ed */

				dl->queue_status = parq_dl_create(dl);
				parq_dl_add_id(dl, id);

				/* All set for request now */
			}
		}
	}

	if (dl == NULL)
		goto ignore;

	if (dl->list_idx != DL_LIST_WAITING) {
		switch (dl->list_idx) {
		case DL_LIST_RUNNING:
			if (dl->status == GTA_DL_ACTIVE_QUEUED)
				parq_download_retry_active_queued(dl);
			g_warning("[PARQ DL] Watch it! Download already running.");
			break;
		case DL_LIST_STOPPED:
			if (parq_debug) {
				g_warning(
					"[PARQ DL] Watch it! Download was stopped (Hashing?)");
			}
			break;
		default:
			g_warning("[PARQ DL] Watch it! Unknown status");
		}

		goto ignore;
	}

	g_assert (dl->list_idx == DL_LIST_WAITING);

	if (has_ip_port)
		download_redirect_to_server(dl, addr, port); /* Might have changed */

	dl->server->parq_version.major = 1;				/* At least */
	dl->server->parq_version.minor = 0;

	/*
	 * Revitalize download, if stopped (aborted, error).
	 */

	if (dl->list_idx == DL_LIST_STOPPED)
		dl->file_info->lifecount++;

	/*
	 * Send the request on the connection the server opened.
	 *
	 * NB: if this is the initial QUEUE request we get after being relaunched,
	 * we won't have a valid queue position to send back, and 0 will be used.
	 */

	if (download_start_prepare(dl)) {
		struct gnutella_socket *ds = dl->socket;
		dl->socket = s;
		ds = s;
#if 0
		d->keep_alive = TRUE;			/* was reset in start_prepare_running */
#endif

		getline_free(ds->getline);		/* No longer need this */
		ds->getline = NULL;


  		g_assert(dl->socket != NULL);
		dl->last_update = tm_time();
		s->resource.download = dl;

		/* Resend request for download */
		download_send_request(dl);
	}

	return;

ignore:
	g_assert(s->resource.download == NULL); /* Hence socket_free() allowed */
	socket_free_null(&s);
	return;
}

/***
 ***  The following section contains upload queueing
 ***/

/**
 * Convert a handle to a `parq_ul_queued' structure.
 */
static inline struct parq_ul_queued *
handle_to_queued(gpointer handle)
{
	struct parq_ul_queued *uq = handle;

	g_assert(handle != NULL);
	g_assert(uq->magic == PARQ_UL_MAGIC);

	return uq;
}

/**
 * removes an parq_ul from the parq list and frees all its memory.
 */
static void
parq_upload_free(struct parq_ul_queued *parq_ul)
{
	g_assert(parq_ul != NULL);
	g_assert(parq_ul->addr_and_name != NULL);
	g_assert(parq_ul->queue != NULL);
	g_assert(parq_ul->queue->size > 0);
	g_assert(parq_ul->queue->by_position != NULL);
	g_assert(parq_ul->by_addr != NULL);
	g_assert(parq_ul->by_addr->total > 0);
	g_assert(parq_ul->by_addr->uploading <= parq_ul->by_addr->total);

	if (parq_ul->u != NULL)
		parq_ul->u->parq_opaque = NULL;

	parq_upload_decrease_all_after(parq_ul);

	if (parq_ul->flags & PARQ_UL_QUEUE)
		ul_parq_queue = g_list_remove(ul_parq_queue, parq_ul);

	parq_ul->by_addr->list = g_list_remove(parq_ul->by_addr->list, parq_ul);
	parq_ul->by_addr->total--;

	if (parq_ul->by_addr->total == 0) {
		g_assert(host_addr_equal(parq_ul->remote_addr, parq_ul->by_addr->addr));
		g_assert(NULL == parq_ul->by_addr->list);

		/* No more uploads from this ip, cleaning up */
		g_hash_table_remove(ul_all_parq_by_addr, &parq_ul->by_addr->addr);
		wfree(parq_ul->by_addr, sizeof *parq_ul->by_addr);

		g_assert(NULL == g_hash_table_lookup(ul_all_parq_by_addr,
								&parq_ul->remote_addr));
	}

	parq_ul->by_addr = NULL;

	/*
	 * Tell parq_upload_update_relative_position not to take this
	 * upload into account when updating the relative position
	 */
	if (parq_ul->is_alive) {
		parq_ul->queue->alive--;
		parq_ul->is_alive = FALSE;
		parq_ul->queue->by_rel_pos =
			  g_list_remove(parq_ul->queue->by_rel_pos, parq_ul);

		/*
		 * Don't update ETA on shutdown, we don't need this information, so
		 * speed up the shutdown process. Also it is better not doing so as on
		 * shutdown not all entries are removed the 'correct' way, we just want
		 * to free the memory
		 */
		if (!parq_shutdown) {
			parq_upload_update_relative_position(parq_ul);
			parq_upload_update_eta(parq_ul->queue);
		}
	} else {
		parq_ul->queue->by_date_dead = g_list_remove(
			  parq_ul->queue->by_date_dead, parq_ul);
	}

	/* Remove the current queued item from all lists */
	parq_ul->queue->by_position =
		g_list_remove(parq_ul->queue->by_position, parq_ul);

	g_hash_table_remove(ul_all_parq_by_addr_and_name, parq_ul->addr_and_name);
	g_hash_table_remove(ul_all_parq_by_id, parq_ul->id);

	g_assert(g_list_find(parq_ul->queue->by_date_dead, parq_ul) == NULL);
	g_assert(g_list_find(parq_ul->queue->by_rel_pos, parq_ul) == NULL);

	/*
	 * Queued upload is now removed from all lists. So queue size can be
	 * safely decreased and new ETAs can be calculate.
	 */
	parq_ul->queue->size--;

	/*
	 * Don't update ETA on shutdown, we don't need this information, so speed
	 * up the shutdown process. Also it is better not doing so as on shutdown
	 * not all entries are removed the 'correct' way, we just want to free
	 * the memory
	 */
	if (!parq_shutdown)
		parq_upload_update_eta(parq_ul->queue);

	/* Free the memory used by the current queued item */
	G_FREE_NULL(parq_ul->addr_and_name);
	atom_sha1_free_null(&parq_ul->sha1);
	parq_ul->sha1 = NULL;
	parq_ul->name = NULL;

	wfree(parq_ul, sizeof *parq_ul);
	parq_ul = NULL;

	if (parq_debug > 3)
		g_message("PARQ UL: Entry freed from memory");
}

/**
 * Calculates the retry delay for an upload.
 *
 * @return the recommended retry delay.
 */
guint32
parq_ul_calc_retry(struct parq_ul_queued *parq_ul)
{
	int result = 60 + 45 * (parq_ul->relative_position - 1);

	/* Used for optimistic mode */
	int fast_result;
	struct parq_ul_queued *parq_ul_prev = NULL;
	GList *l = NULL;
	guint avg_bps;

	if (parq_optimistic) {
		avg_bps = bsched_avg_bps(bsched_bws_out());
		avg_bps = MAX(1, avg_bps);

		l = g_list_find(parq_ul->queue->by_rel_pos, parq_ul);

		if (l == NULL)
			l = g_list_last(parq_ul->queue->by_position);

		if (l == NULL)
			return MIN(PARQ_MAX_UL_RETRY_DELAY, result);

		if (l->prev != NULL) {
			parq_ul_prev = l->prev->data;

			g_assert(parq_ul_prev != NULL);

			fast_result = parq_ul_prev->chunk_size / avg_bps * max_uploads;

			result = MIN(result, fast_result);
		}
	}

	return MIN(PARQ_MAX_UL_RETRY_DELAY, result);
}

/**
 * Creates a new upload structure and prefills some values. Returns a pointer to
 * the newly created ul_queued structure.
 */
static struct parq_ul_queued *
parq_upload_create(gnutella_upload_t *u)
{
	time_t now = tm_time();
	struct parq_ul_queued *parq_ul = NULL;
	struct parq_ul_queued *parq_ul_prev = NULL;
	struct parq_ul_queue *parq_ul_queue = NULL;
	guint eta = 0;
	guint rel_pos = 1;
	GList *l;

	g_assert(u != NULL);
	g_assert(ul_all_parq_by_addr_and_name != NULL);
	g_assert(ul_all_parq_by_id != NULL);

	parq_ul_queue = parq_upload_which_queue(u);
	g_assert(parq_ul_queue != NULL);

	/* Locate the previous queued item so we can calculate the ETA */
	l = g_list_last(parq_ul_queue->by_position);
	if (l != NULL)
		parq_ul_prev = l->data;

	if (parq_ul_prev != NULL) {
		rel_pos = parq_ul_prev->relative_position;
		if (parq_ul_prev->is_alive)
			rel_pos++;

		eta = parq_ul_prev->eta;

		if (max_uploads <= 0) {
			eta = (guint) -1;
		} else if (parq_ul_prev->is_alive) {
			guint avg_bps;

			avg_bps = bsched_avg_bps(bsched_bws_out());
			avg_bps = MAX(1, avg_bps);

			if (parq_optimistic)
				eta += (parq_ul_prev->file_size / avg_bps * max_uploads) / 
					(parq_ul_prev->sha1 != NULL ? 
					 	dmesh_count(parq_ul_prev->sha1) + 1 : 1);
			else
				eta += parq_ul_prev->file_size / avg_bps * max_uploads;
		}
	}

	/* Create new parq_upload item */
	parq_ul = walloc0(sizeof *parq_ul);
	g_assert(parq_ul != NULL);

	/* Create identifier to find upload again later. IP + Filename */
	parq_ul->remote_addr = u->addr;
	parq_upload_update_addr_and_name(parq_ul, u);
	parq_ul->sha1 = u->sha1 ? atom_sha1_get(u->sha1) : NULL;

	/* Create an ID */
	guid_random_muid(parq_ul->id);

	g_assert(parq_ul->addr_and_name != NULL);

	/* Fill parq_ul structure */
	parq_ul->magic = PARQ_UL_MAGIC;
	parq_ul->position = ++parq_ul_queue->size;
	parq_ul->relative_position = rel_pos;
	parq_ul->eta = eta;
	parq_ul->enter = now;
	parq_ul->updated = now;
	parq_ul->file_size = u->file_size;
	parq_ul->queue = parq_ul_queue;
	parq_ul->has_slot = FALSE;
	parq_ul->addr = zero_host_addr;
	parq_ul->port = 0;
	parq_ul->major = 0;
	parq_ul->minor = 0;
	parq_ul->active_queued = FALSE;
	parq_ul->is_alive = TRUE;
	parq_ul->had_slot =  FALSE;
	parq_ul->quick = FALSE;
	parq_ul->queue->alive++;
	/*
	 * On create, set the retry to now. If we use the
	 * now + parq_ul_calc_retry method, the new request
	 * would immediatly be followed by a requested to soon
	 * error.
	 */
	parq_ul->retry = now;
	parq_ul->expire = parq_ul->retry + MIN_LIFE_TIME;
	parq_ul->ban_timeout = 0;
	parq_ul->disc_timeout = 0;
	parq_ul->uploaded_size = 0;

	/* Save into hash table so we can find the current parq ul later */
	g_hash_table_insert(ul_all_parq_by_id, parq_ul->id, parq_ul);

	parq_ul_queue->by_position =
		g_list_append(parq_ul_queue->by_position, parq_ul);

	parq_ul_queue->by_rel_pos =
		g_list_append(parq_ul_queue->by_rel_pos, parq_ul);

	if (parq_debug > 3) {
		g_message("PARQ UL Q %d/%d (%3d[%3d]/%3d): New: %s \"%s\"; ID=\"%s\"",
			g_list_position(ul_parqs,
				g_list_find(ul_parqs, parq_ul->queue)) + 1,
			g_list_length(ul_parqs),
			parq_ul->position,
			parq_ul->relative_position,
			parq_ul->queue->size,
			host_addr_to_string(parq_ul->remote_addr),
			parq_ul->name,
			guid_hex_str(parq_ul->id));
	}

	/* Check if the requesting client has already other PARQ entries */
	parq_ul->by_addr = g_hash_table_lookup(ul_all_parq_by_addr,
							&parq_ul->remote_addr);

	if (parq_ul->by_addr == NULL) {
		/* The requesting client has no other PARQ entries yet, create an ip
		 * reference structure */
		parq_ul->by_addr = walloc0(sizeof *parq_ul->by_addr);
		parq_ul->by_addr->addr = parq_ul->remote_addr;
		g_hash_table_insert(ul_all_parq_by_addr,
				&parq_ul->by_addr->addr, parq_ul->by_addr);
		parq_ul->by_addr->uploading = 0;
		parq_ul->by_addr->total = 0;
		parq_ul->by_addr->list = NULL;
	}

	g_assert(host_addr_equal(parq_ul->by_addr->addr, parq_ul->remote_addr));

	parq_ul->by_addr->total++;
	parq_ul->by_addr->list = g_list_prepend(parq_ul->by_addr->list, parq_ul);

	g_assert(parq_ul != NULL);
	g_assert(parq_ul->position > 0);
	g_assert(parq_ul->addr_and_name != NULL);
	g_assert(parq_ul->name != NULL);
	g_assert(parq_ul->queue != NULL);
	g_assert(parq_ul->queue->by_position != NULL);
	g_assert(parq_ul->queue->by_rel_pos != NULL);
	g_assert(parq_ul->queue->by_position->data != NULL);
	g_assert(parq_ul->relative_position > 0);
	g_assert(parq_ul->relative_position <= (guint) parq_ul->queue->size);
	g_assert(parq_ul->by_addr != NULL);
	g_assert(parq_ul->by_addr->uploading <= parq_ul->by_addr->total);

	return parq_ul;
}

/**
 * Looks up in which queue the current upload should be placed and if the queue
 * doesn't exist yet it will be created.
 *
 * @return a pointer to the queue in which the upload should be queued.
 */
static struct parq_ul_queue *
parq_upload_which_queue(gnutella_upload_t *u)
{
	struct parq_ul_queue *queue;
	guint size = PARQ_UL_LARGE_SIZE;
	guint slot;

	/*
	 * Determine in which queue the upload should be placed. Upload queues:
	 * 300 Mi < size < oo
	 * 150 Mi < size <= 300 Mi
	 *  75 Mi < size <= 150 Mi
	 *   0 Mi < size <= 75 Mi
	 * Smallest: PARQ_UL_LARGE_SIZE / 2^(parq_upload_slots-1)
	 *
	 * If the size doesn't fit in any of the first n-1 queues, it is put
	 * into the last queue implicitly.
	 */

	for (slot = 1 ; slot < max_uploads; slot++) {
		if (u->file_size > size)
			break;
		size = size / 2;
	}

	/* if necessary, create missing queues */
	while (g_list_length(ul_parqs) < max_uploads)
		parq_upload_new_queue();

	queue = g_list_nth_data(ul_parqs, slot - 1);

	/* We might need to reactivate the queue */
	queue->active = TRUE;

	g_assert(queue != NULL);
	g_assert(queue->active == TRUE);

	return queue;
}

/**
 * Creates a new parq_ul_queue structure and places it in the ul_parqs
 * linked list.
 */
static struct parq_ul_queue *
parq_upload_new_queue(void)
{
	struct parq_ul_queue *queue = NULL;

	queue = walloc(sizeof(*queue));
	g_assert(queue != NULL);

	queue->size = 0;
	queue->active = TRUE;
	queue->by_position = NULL;
	queue->by_rel_pos = NULL;
	queue->by_date_dead = NULL;
	queue->active_uploads = 0;
	queue->alive = 0;

	ul_parqs = g_list_append(ul_parqs, queue);

	if (parq_debug)
		g_message("PARQ UL: Created new queue %d",
			g_list_position(ul_parqs, g_list_find(ul_parqs, queue)) + 1);

	g_assert(ul_parqs != NULL);
	g_assert(ul_parqs->data != NULL);
	g_assert(queue != NULL);

	return queue;
}

/**
 * Frees the queue from memory and the ul_parqs linked list.
 */
static void
parq_upload_free_queue(struct parq_ul_queue *queue)
{
	g_assert(queue != NULL);
	g_assert(ul_parqs != NULL);

	/* Never ever remove a queue which is in use and/or marked as active */
	g_assert(queue->size == 0);
	g_assert(queue->active_uploads == 0);
	g_assert(queue->active == FALSE);

	if (parq_debug)
		g_message("PARQ UL: Removing inactive queue %d",
				g_list_position(ul_parqs, g_list_find(ul_parqs, queue)) + 1);

	/* Remove queue from all lists */
	ul_parqs = g_list_remove(ul_parqs, queue);

	/* Free memory */
	wfree(queue, sizeof(*queue));
	queue = NULL;
}

/**
 * Updates the ETA of all queued items in the given queue.
 */
static void
parq_upload_update_eta(struct parq_ul_queue *which_ul_queue)
{
	GList *l;
	guint eta = 0;
	guint avg_bps;

	avg_bps = bsched_avg_bps(bsched_bws_out());
	avg_bps = MAX(1, avg_bps);

	if (which_ul_queue->active_uploads) {
		/*
		 * Current queue has an upload slot. Use this one for a start ETA.
		 * Locate the first active upload in this queue.
		 */

		for (l = which_ul_queue->by_position; l; l = g_list_next(l)) {
			struct parq_ul_queued *parq_ul = l->data;

			if (parq_ul->has_slot) {		/* Recompute ETA */
				eta += parq_ul->file_size / avg_bps * max_uploads;
				break;
			}
		}
	}

	if (eta == 0 && ul_running > max_uploads) {
		/* We don't have an upload slot available, so a start ETA (for position
		 * 1) is necessary.
		 * Use the eta of another queue. First by the queue which uses more than
		 * one upload slot. If that result is still 0, we have a small problem
		 * as the ETA can't be calculated correctly anymore.
		 */

		for (l = ul_parqs; l; l = g_list_next(l)) {
			struct parq_ul_queue *q = l->data;

			if (q->active_uploads > 1) {
				struct parq_ul_queued *parq_ul = q->by_rel_pos->data;

				eta = parq_ul->eta;
				break;
			}
		}

		if (eta == 0)
			g_warning("[PARQ UL] Was unable to calculate an accurate ETA");

	}

	for (l = which_ul_queue->by_rel_pos; l; l = g_list_next(l)) {
		struct parq_ul_queued *parq_ul = l->data;

		g_assert(parq_ul->is_alive);

		parq_ul->eta = eta;

		if (parq_ul->has_slot)
			continue;			/* Skip already uploading uploads */

		/* Recalculate ETA */
		if (parq_optimistic)
			eta += (parq_ul->file_size / avg_bps * max_uploads) /
				(parq_ul->sha1 != NULL ? dmesh_count(parq_ul->sha1) + 1 : 1);
		else
			eta += parq_ul->file_size / avg_bps * max_uploads;

	}
}

static struct parq_ul_queued *
parq_upload_find_id(header_t *header)
{
	gchar *buf;

	buf = header_get(header, "X-Queued");
	if (buf != NULL) {
		const gchar *id_str = get_header_value(buf, "ID", NULL);

		if (id_str) {
			gchar id[GUID_RAW_SIZE];
			
			if (hex_to_guid(id_str, id)) {
				return g_hash_table_lookup(ul_all_parq_by_id, id);
			}
			/**
			 * Due to bugs, gtk-gnutella <= 0.96.3 sent a raw binary ID
			 * instead of a hex-encoded ID. We should be able to recover
			 * it in most cases unless it contains character that clash
			 * with parsing (NULL, control chars, etc.).
			 */
			if (parq_debug) {
				g_message("parq_upload_find_id(): hex_to_guid() failed, "
					"retrying with bug workaround");
			}
			strncpy(id, id_str, sizeof id);
			return g_hash_table_lookup(ul_all_parq_by_id, id);
		}
		g_warning("[PARQ UL] missing ID in PARQ request");
		if (parq_debug) {
			g_warning("[PARQ UL] header dump:");
			header_dump(header, stderr);
		}
	}
	return NULL;
}

/**
 * Finds an upload if available in the upload queue.
 *
 * @return NULL if upload could not be found.
 */
static inline struct parq_ul_queued *
parq_upload_find(const gnutella_upload_t *u)
{
	gchar buf[1024 + 128];

	g_assert(u != NULL);
	g_assert(ul_all_parq_by_addr_and_name != NULL);
	g_assert(ul_all_parq_by_id != NULL);

	if (u->parq_opaque != NULL)
		return u->parq_opaque;

	/* Can't lookup an upload with no name */
	if (u->name == NULL)
		return NULL;

	gm_snprintf(buf, sizeof(buf), "%s %s",
		host_addr_to_string(u->addr), u->name);

	return g_hash_table_lookup(ul_all_parq_by_addr_and_name, buf);
}

/**
 * Removes any PARQ uploads which show no activity.
 */
void
parq_upload_timer(time_t now)
{
	static guint print_q_size = 0;
	static guint startup_delay = 0;
	GList *queues, *dl;
	GSList *sl, *to_remove = NULL;
	guint	queue_selected = 0;
	gboolean rebuilding = FALSE;

	/*
	 * Don't do anything with parq during the first 10 seconds. Looks like
	 * PROP_LIBRARY_REBUILDING is not set yet immediatly at the first time, so
	 * there may be some other things not set properly yet neither.
	 */
	if (startup_delay < 10) {
		startup_delay++;
		return;
	}


	/* PARQ ip banning timer */
	for (dl = parq_banned_sources ; dl != NULL; dl = g_list_next(dl)) {
		struct parq_banned *banned = dl->data;

		if (now - banned->added > PARQ_MAX_UL_RETRY_DELAY ||
			now - banned->expire > 0) {
			to_remove = g_slist_prepend(to_remove, banned);
		}
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct parq_banned *banned = sl->data;

		parq_del_banned_source(banned->addr);
	}

	g_slist_free(to_remove);
	to_remove = NULL;

	for (queues = ul_parqs ; queues != NULL; queues = queues->next) {
		struct parq_ul_queue *queue = queues->data;

		queue_selected++;

		/*
		 * Infrequently scan the dead uploads as well to send QUEUE.
		 * NB: if max_uploads == 0, they disabled sharing: don't send QUEUE.
		 */

		if ((now % 60) == 0 && max_uploads > 0) {
			for (dl = queue->by_date_dead; dl != NULL; dl = g_list_next(dl)) {
				struct parq_ul_queued *parq_ul = dl->data;

				g_assert(parq_ul != NULL);

				/* Entry can't have a slot, and we know it expired! */

				if (
					!(parq_ul->flags & (PARQ_UL_QUEUE|PARQ_UL_NOQUEUE)) &&
					delta_time(parq_ul->send_next_queue, now) < 0 &&
					parq_ul->queue_sent < MAX_QUEUE &&
					parq_ul->queue_refused < MAX_QUEUE_REFUSED &&
					!ban_is_banned(parq_ul->remote_addr) &&
					parq_still_sharing(parq_ul)
				)
					parq_upload_register_send_queue(parq_ul);
			}
		}

		for (dl = queue->by_rel_pos; dl != NULL; dl = g_list_next(dl)) {
			struct parq_ul_queued *parq_ul = dl->data;

			g_assert(parq_ul != NULL);


			if (
				parq_ul->expire <= now &&
				!parq_ul->has_slot &&
				!(parq_ul->flags & (PARQ_UL_QUEUE|PARQ_UL_NOQUEUE)) &&
				delta_time(parq_ul->send_next_queue, now) < 0 &&
				parq_ul->queue_sent < MAX_QUEUE &&
				parq_ul->queue_refused < MAX_QUEUE_REFUSED &&
				max_uploads > 0 &&
				!ban_is_banned(parq_ul->remote_addr) &&
				parq_still_sharing(parq_ul)
			)
				parq_upload_register_send_queue(parq_ul);

			if (
				parq_ul->is_alive &&
				parq_ul->expire + PARQ_GRACE_TIME < now &&
				!parq_ul->has_slot &&
				!(parq_ul->flags & PARQ_UL_QUEUE)	/* No timeout if pending */
			) {
				if (parq_debug > 3)
					g_message("PARQ UL Q %d/%d (%3d[%3d]/%3d): "
						"Timeout: %s '%s'",
						g_list_position(ul_parqs,
							g_list_find(ul_parqs, parq_ul->queue)) + 1,
						g_list_length(ul_parqs),
						parq_ul->position,
						parq_ul->relative_position,
						parq_ul->queue->size,
						host_addr_to_string(parq_ul->remote_addr),
						parq_ul->name);


				/*
			 	 * Mark for removal. Can't remove now as we are still using the
			 	 * ul_parq_by_position linked list. (prepend is probably the
				 * fastest function
			 	 */
				to_remove = g_slist_prepend(to_remove, parq_ul);
			}
		}

		/*
		 * Mark queue as inactive when there are less uploads slots available.
		 */
		if (queue_selected > max_uploads)
			queue->active = FALSE;
		else
			queue->active = TRUE;
	}


	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct parq_ul_queued *parq_ul = sl->data;

		parq_ul->is_alive = FALSE;
		parq_ul->queue->alive--;

		parq_ul->queue->by_rel_pos =
			  g_list_remove(parq_ul->queue->by_rel_pos, parq_ul);

		parq_upload_update_relative_position(parq_ul);
		parq_upload_update_eta(parq_ul->queue);

		g_assert(parq_ul->queue->alive >= 0);
		if (enable_real_passive && parq_still_sharing(parq_ul)) {
			parq_ul->queue->by_date_dead =
			g_list_append(parq_ul->queue->by_date_dead, parq_ul);
		} else
			parq_upload_free(sl->data);
	}

	g_slist_free(to_remove);
	to_remove = NULL;

	/* Save queue info every 60 seconds */
	if (print_q_size++ >= 60) {
		print_q_size = 0;

		if (parq_debug) {

			for (queues = ul_parqs ; queues != NULL; queues = queues->next) {
				struct parq_ul_queue *queue = queues->data;

				g_message("PARQ UL: Queue %d/%d contains %d items, "
					  "%d uploading, %d alive, queue is marked %s",
					  g_list_position(ul_parqs, g_list_find(ul_parqs, queue))
						  + 1,
					  g_list_length(ul_parqs),
					  queue->size,
					  queue->active_uploads,
					  queue->alive,
					  queue->active ? "active" : "inactive");
			}
		}

		parq_upload_save_queue();

	}

	/*
	 * If the last queue is not active anymore (ie it should be removed
	 * as soon as the queue is empty) and there are no more queued items
	 * in the queue, remove the queue.
	 */
	queues = g_list_last(ul_parqs);

	if (queues != NULL) {
		struct parq_ul_queue *queue = queues->data;
		if (!queue->active && queue->size == 0) {
			parq_upload_free_queue(queue);
		}
	}

	/*
	 * Send one QUEUE command at a time, until we have MAX_UPLOADS uploads
	 * NB: if max_uploads is 0, then they disabled sharing: don't send QUEUE.
	 */

	gnet_prop_get_boolean_val(PROP_LIBRARY_REBUILDING, &rebuilding);

	if (!rebuilding && ul_parq_queue != NULL && max_uploads > 0) {
		GList *queue_cmd_remove = NULL;
		GList *queue_cmd_list = NULL;

		queue_cmd_list = ul_parq_queue;
		do {
			struct parq_ul_queued *parq_ul = queue_cmd_list->data;

			/*
			 * If a previous QUEUE command could not connect to this IP during
			 * this timeframe, we can safely ignore all QUEUE commands for this
			 * IP now.
			 */
			if (
				now >= parq_ul->by_addr->last_queue_sent +
					(gint) upload_connecting_timeout &&
				parq_ul->by_addr->last_queue_sent >
					parq_ul->by_addr->last_queue_connected &&
				delta_time(parq_ul->send_next_queue, now) < 0
			) {

				if (parq_debug > 3)
					g_message("PARQ UL: Removing QUEUE command due to other "
						"failed QUEUE command for ip: %s",
						host_addr_to_string(parq_ul->by_addr->addr));

				parq_ul->last_queue_sent = parq_ul->by_addr->last_queue_sent;
				queue_cmd_remove = g_list_prepend(queue_cmd_remove, parq_ul);

				parq_ul->flags &= ~PARQ_UL_QUEUE;
				continue;
			}

			/*
			 * Don't send queue if the current IP has another pending connecting
			 * QUEUE.
			 */
			if (
				parq_ul->by_addr->last_queue_sent + (gint) upload_connecting_timeout >=
					now &&
				parq_ul->by_addr->last_queue_sent >
					parq_ul->by_addr->last_queue_connected
				) {

					if (parq_debug > 3) {
						g_message("PARQ UL: Not sending QUEUE command due to "
							"another pending QUEUE command for ip: %s",
							host_addr_to_string(parq_ul->by_addr->addr));
					}
					continue;
			}

			parq_upload_send_queue(parq_ul);

			queue_cmd_remove = g_list_prepend(queue_cmd_remove, parq_ul);

			parq_ul->flags &= ~PARQ_UL_QUEUE;
		} while (
			ul_registered < MAX_UPLOADS &&
			(queue_cmd_list = g_list_next(queue_cmd_list)) != NULL &&
			bws_can_connect(SOCK_TYPE_UPLOAD)
		);

		while (g_list_first(queue_cmd_remove) != NULL) {
			ul_parq_queue =
				g_list_remove(ul_parq_queue, queue_cmd_remove->data);
			queue_cmd_remove =
				g_list_remove(queue_cmd_remove, queue_cmd_remove->data);
		}
	}
}

/**
 * @return TRUE if parq cannot hold any more uploads.
 */
gboolean
parq_upload_queue_full(gnutella_upload_t *u)
{
	struct parq_ul_queue *q_ul = NULL;
	struct parq_ul_queued *parq_ul = NULL;

	q_ul = parq_upload_which_queue(u);
	g_assert(q_ul->size >= q_ul->alive);

	if ((guint32) q_ul->size < parq_max_upload_size)
		return FALSE;

	if (q_ul->by_date_dead == NULL ||
		  g_list_first(q_ul->by_date_dead) == NULL) {
		return TRUE;
	}

	g_assert(q_ul->by_date_dead != NULL);

	if (parq_debug > 2)
		g_message("PARQ UL: Removing a 'dead' upload");

	parq_ul = g_list_first(q_ul->by_date_dead)->data;
	parq_upload_free(parq_ul);

	return FALSE;
}

/**
 * Whether the current upload is already queued.
 */
gboolean
parq_upload_queued(gnutella_upload_t *u)
{
	return parq_upload_lookup_position(u) != (guint) -1;
}

/**
 * Get parq structure at specified position.
 */
struct parq_ul_queued *
parq_upload_get_at(struct parq_ul_queue *queue, int position)
{
	return g_list_nth_data(queue->by_rel_pos, position - 1);
}

/**
 * Check that the IP is not already downloading more than is alllowed.
 *
 * @return TRUE if it is OK for that IP to download from us.
 */
gboolean
parq_upload_addr_can_proceed(const gnutella_upload_t *u)
{
	struct parq_ul_queued *uq = u->parq_opaque;

	g_assert(uq != NULL);

	return ((guint32) uq->by_addr->uploading >= max_uploads_ip) ? FALSE : TRUE;
}

/**
 * @return TRUE if the current upload will finish quickly enough and 
 * actually scheduling would only cost more resources then it would
 * save.
 */
static gboolean
parq_upload_quick_continue(struct parq_ul_queued *uq, gint used_slots)
{
	guint avg_bps;
	filesize_t total;

	g_assert(uq);

	/*
	 * Compute total amount of data that has been requested by the remote
	 * host so far, adding the current request size to the already downloaded
	 * amount.
	 */

	total = uq->uploaded_size + uq->chunk_size;

	if (total < parq_size_always_continue)
		return TRUE;

	if (parq_time_always_continue > 0) {
		avg_bps = bsched_avg_bps(bsched_bws_out());
		avg_bps = MAX(1, avg_bps);

		/*
		 * Determine the time this upload would need. Add + 1 to the
		 * number of used_slots to also include this upload in the
		 * calculation.
		 */
		if (total * (used_slots + 1) / avg_bps <= parq_time_always_continue)
			return TRUE;
	}

	return FALSE;
}

/**
 * @return TRUE if the current upload is allowed to get an upload slot.
 */
static gboolean
parq_upload_continue(struct parq_ul_queued *uq, gint used_slots)
{
	GList *l = NULL;
	gint free_slots = max_uploads - used_slots;
	gint slots_free = max_uploads;	/* Free slot calculater */
	gboolean quick_allowed = FALSE;

	/*
	 * max_uploads holds the number of upload slots a queue may currently
	 * use. This is the lowest number of upload slots used by a queue + 1.
	 */
	gint allowed_max_uploads = -1;

	g_assert(uq != NULL);

	if (parq_debug >= 5)
		g_message("[PARQ UL] parq_upload_continue, free_slots %d", free_slots);

	/*
	 * If there are no free upload slots the queued upload isn't allowed an
	 * upload slot anyway. So we might just as well abort here.
	 */

	if (free_slots <= 0)
		goto check_quick;

	/*
	 * Don't allow more than max_uploads_ip per single host (IP)
	 */
	if ((guint32) uq->by_addr->uploading >= max_uploads_ip) {
		if (parq_debug >= 5)
			g_message("[PARQ UL] parq_upload_continue, "
				"max_uploads_ip per single host reached %d/%d",
				uq->by_addr->uploading, max_uploads_ip);
		goto check_quick;
	}

	/*
	 * If the number of upload slots have been decreased, an old queue
	 * may still exist. What to do with those uploads? Should we make
	 * sure those uploads are served first? Those uploads should take
	 * less time to upload anyway, as they _must_ be smaller.
	 */

	l = g_list_last(ul_parqs);
	{
		struct parq_ul_queue *queue = l->data;
		if (!queue->active && queue->alive > 0) {
			if (uq->queue->active) {
				if (parq_debug)
					g_message("[PARQ UL] Upload in inactive queue first");
				goto check_quick;
			}
		}
	}

	/*
	 * 1) First check if another queue 'needs' an upload slot.
	 * 2) Avoid  one queue getting almost all upload slots.
	 * 3) Then, check if the current upload is allowed this upload slot.
	 */

	/*
	 * Step 1. Check if another queues must have an upload.
	 *         That is when the current queue has no active uploads while there
	 *         are uploads alive.
	 * Step 2. Avoid one queue getting almost all upload slots.
	 *
	 * This is done by determining how many upload slots every queue is using,
	 * and if the queue would like to have another upload slot.
	 */

	for (l = g_list_last(ul_parqs); l; l = l->prev) {
		struct parq_ul_queue *queue = l->data;
		if (queue->alive > queue->active_uploads) {
			/* Queue would like to get another upload slot */
			if ((guint) allowed_max_uploads > (guint) queue->active_uploads) {
				/*
				 * Determine the current maximum of upload
				 * slots allowed compared to other queus.
				 */
				allowed_max_uploads = queue->active_uploads + 1;
			}
		}
		if (queue->alive > 0)
			slots_free--;
	}

	/* This is to ensure dynamic slot allocation */
	if (slots_free < 0)
		slots_free = 0;

	if (parq_optimistic)
		slots_free = 0;

	if (allowed_max_uploads <= uq->queue->active_uploads - slots_free) {
		if (parq_debug >= 5)
			g_message("[PARQ UL] parq_upload_continue max_uploads reached "
				"(%d-%d)/%d",
				uq->queue->active_uploads, slots_free,
				allowed_max_uploads);
		goto check_quick;
	}

	/*
	 * Step 3. Check if current upload may have this slot
	 *         That is when the current upload is the first upload in its
	 *         queue which has no upload slot. Or if a earlier queued item is
	 *		   already downloading something in another queue.
	 */

	for (l = g_list_first(uq->queue->by_rel_pos); l; l = g_list_next(l)) {
		struct parq_ul_queued *parq_ul = l->data;

		if (
			  !parq_ul->has_slot && parq_ul != uq &&
			  !host_addr_equal(parq_ul->by_addr->addr, uq->by_addr->addr) &&
			  !parq_ul->by_addr->uploading
			) {
			/* Another upload in the current queue is allowed first */
			if (slots_free < 0) {
				if (parq_debug >= 4)
					g_message("[PARQ UL] Another upload in other queue first");
				goto check_quick;
			}
			slots_free--;
		} else if (
				parq_ul == uq ||
				host_addr_equal(parq_ul->by_addr->addr, uq->by_addr->addr)
		) {
			/*
			 * So the current upload is the first in line (we would have
			 * returned FALSE otherwise by now).
			 * We also check on ip slot (instead of only the requested file-
			 * name). This is allowed as PARQ is a slot reservation system. So
			 * we check if the requesting host has another queued item which
			 * is allowed to continue. We will just use that position here then.
			 */
			if (parq_debug)
				g_message("[PARQ UL] Allowing upload");
			return TRUE;
		}
	}

check_quick:
	/*
	 * Let the download continue if the request is small enough though.
	 * This check must be done only when we would otherwise refuse a
	 * normal slot for this upload.  Indeed, when its quota is exhausted,
	 * it will be queued back.
	 */

	quick_allowed = parq_upload_quick_continue(uq, used_slots);

	/*
	 * If uploads are stalling, we're already short in bandwidth.  Don't
	 * add to the clogging of the output link.
	 */

	if (uploads_stalling && quick_allowed) {
		if (parq_debug)
			g_message("[PARQ UL] No quick upload of %ld bytes (stalling)",
				(gulong) uq->chunk_size);
		quick_allowed = FALSE;
	}

	if (quick_allowed) {
		if (parq_debug)
			g_message("[PARQ UL] Allowed quick upload (%ld bytes)",
				(gulong) uq->chunk_size);
		uq->quick = TRUE;
		return TRUE;
	}

	return FALSE;
}

/**
 * Updates the IP and name entry in the queued structure and makes sure the hash
 * table remains in sync
 */
static void
parq_upload_update_addr_and_name(struct parq_ul_queued *parq_ul,
	gnutella_upload_t *u)
{
	g_assert(parq_ul != NULL);
	g_assert(u != NULL);
	g_assert(u->name != NULL);

	if (parq_ul->addr_and_name != NULL) {
		g_hash_table_remove(ul_all_parq_by_addr_and_name,
			parq_ul->addr_and_name);
		G_FREE_NULL(parq_ul->addr_and_name);
		parq_ul->name = NULL;
	}

	parq_ul->addr_and_name = g_strdup_printf("%s %s",
								host_addr_to_string(u->addr), u->name);
	parq_ul->name = strchr(parq_ul->addr_and_name, ' ') + 1;

	g_hash_table_insert(ul_all_parq_by_addr_and_name, parq_ul->addr_and_name,
		parq_ul);
}

/**
 * Function used to keep the relative position list sorted by relative position.
 * It should never be possible for 2 downloads to have the same relative
 * position in the same queue.
 */
static gint
parq_ul_rel_pos_cmp(gconstpointer a, gconstpointer b)
{
	const struct parq_ul_queued *as = a, *bs = b;

	g_assert(as->relative_position != bs->relative_position);

	return as->relative_position - bs->relative_position;
}

void
parq_upload_upload_got_cloned(gnutella_upload_t *u, gnutella_upload_t *cu)
{
	struct parq_ul_queued *parq_ul;

	if (u->parq_opaque == NULL) {
		g_assert(cu->parq_opaque == NULL);
		return;
	}

	g_assert(u->parq_opaque != NULL);
	g_assert(cu->parq_opaque != NULL);

	parq_ul = parq_upload_find(u);

	if (parq_ul != NULL)
		parq_ul->u = cu;

	u->parq_opaque = NULL;

	g_assert(u->parq_opaque == NULL);
	g_assert(cu->parq_opaque != NULL);
}

/**
 * Makes sure parq doesn't keep any internal reference to the upload structure
 */
void
parq_upload_upload_got_freed(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;

	if (u->parq_opaque == NULL)
		return;

	parq_ul = parq_upload_find(u);

	/*
	 * If the u->parq_opaque exist there must be a reference to an parq
	 * structure. Otherwise something did go wrong.
	 */
	g_assert(parq_ul != NULL);

	parq_ul->u = NULL;

	u->parq_opaque = NULL;
}

/**
 * Get a queue slot, either existing or new.
 *
 * When `replacing' is TRUE, they issued a new request for a possibly
 * stalling entry, which was killed anyway, so give them a slot!
 *
 * @return slot as an opaque handle, NULL if slot cannot be created.
 */
gpointer
parq_upload_get(gnutella_upload_t *u, header_t *header, gboolean replacing)
{
	struct parq_ul_queued *parq_ul = NULL;
	gchar *buf;

	g_assert(u != NULL);
	g_assert(header != NULL);

	/*
	 * Try to locate by ID first. If this fails, try to locate by IP and file
	 * name. We want to locate on ID first as a client may reuse an ID.
	 * Avoid abusing a PARQ entry by reusing an ID which already finished
	 * uploading.
	 */

	parq_ul = parq_upload_find_id(header);

	if (parq_ul != NULL) {
		if (!parq_ul->had_slot)
			goto cleanup;
		if (!replacing)
			parq_ul = NULL;
	}

	if (parq_ul == NULL)
		parq_ul = parq_upload_find(u);

	if (parq_ul == NULL) {
		/*
		 * Current upload is not queued yet. If the queue isn't full yet,
		 * always add the upload in the queue.
		 */

		if (parq_upload_queue_full(u))
			return NULL;

		parq_ul = parq_upload_create(u);

		g_assert(parq_ul != NULL);

		if (parq_debug >= 3)
			g_message("[PARQ UL] Q %d/%d (%3d[%3d]/%3d) "
				"ETA: %s Added: %s '%s'",
				g_list_position(ul_parqs,
					g_list_find(ul_parqs, parq_ul->queue)) + 1,
				g_list_length(ul_parqs),
				parq_ul->position,
				parq_ul->relative_position,
				parq_ul->queue->size,
				short_time(parq_upload_lookup_eta(u)),
				host_addr_to_string(parq_ul->remote_addr),
				parq_ul->name);
	}

cleanup:
	g_assert(parq_ul != NULL);

	if (parq_ul->u != NULL) {
		if (parq_ul->u != u) {
			g_warning("[PARQ UL] Request from ip %s (%s), requested a new "
				"upload %s while another one is still active within PARQ",
				host_addr_to_string(u->addr), upload_vendor_str(u), u->name);
			return NULL;
		}
	}

	if (parq_ul->queue->by_date_dead != NULL &&
		  g_list_find(parq_ul->queue->by_date_dead, parq_ul) != NULL)
		parq_ul->queue->by_date_dead =
			  g_list_remove(parq_ul->queue->by_date_dead, parq_ul);

	/*
	 * It is possible the client reused its ID for another file name, which is
	 * a valid thing to do. So make sure we have still got the IP and name
	 * in sync
	 */

	parq_upload_update_addr_and_name(parq_ul, u);

	if (!parq_ul->is_alive) {
		parq_ul->queue->alive++;
		parq_ul->is_alive = TRUE;
		parq_upload_update_relative_position(parq_ul);
		g_assert(parq_ul->queue->alive > 0);

		/* Insert again, in the relative position list. */
		parq_ul->queue->by_rel_pos =
			g_list_insert_sorted(parq_ul->queue->by_rel_pos, parq_ul,
				  parq_ul_rel_pos_cmp);
		parq_upload_update_eta(parq_ul->queue);
	}

	buf = header_get(header, "X-Queue");

	if (buf != NULL)			/* Remote server does support queues */
		get_header_version(buf, &parq_ul->major, &parq_ul->minor);

	/*
	 * Update listening IP and port information
	 *
	 * Specs 1.0 defined X-Listen-IP, but 1.0.a corrected to X-Node.
	 * Parse both, but only emit X-Node from now on.
	 *		--RAM, 11/05/2003
	 */

	if (parq_ul->major >= 1) {					/* Only if PARQ advertised */
		GList *l = NULL;

		buf = header_get(header, "X-Node");
		if (buf == NULL)
			buf = header_get(header, "X-Listen-Ip");	/* Case normalized */

		if (buf != NULL) {
			/*
			 * Update port / IP entries for other queued entries too.
			 *
			 * XXX We should lookup the IP:Port combo. Multiple clients
			 * XXX could be running from the same IP. We shouldn't update those
			 * XXX entries. However, evil clients might abuse this and run from
			 * XXX multiple ports.
			 */

			for (l = parq_ul->by_addr->list; l != NULL; l = g_list_next(l)) {
				struct parq_ul_queued *parq_ul_up = l->data;

				string_to_host_addr_port(buf, NULL,
					&parq_ul_up->addr, &parq_ul_up->port);
				parq_ul_up->flags &= ~PARQ_UL_NOQUEUE;
			}
		}
	}

	/* Save pointer to structure. Don't forget to move it to
     * the cloned upload or remove the pointer when the struct
     * is freed
	 */

	parq_ul->u = u;

	return parq_ul;
}

/**
 * If the download may continue, true is returned. False otherwise (which
 * probably means the upload is queued).
 * Where parq_upload_request honours the number of upload slots, this one
 * is used for dynamic slot allocation.
 * This function expects that the upload was checked with parq_upload_request
 * first.
 */
gboolean
parq_upload_request_force(gnutella_upload_t *u, gpointer handle,
	guint used_slots)
{
	struct parq_ul_queued *parq_ul = handle_to_queued(handle);

	/*
	 * Check whether the current upload is allowed to get an upload slot. If so
	 * move other queued items after the current item up one position in the
	 * queue
	 */
	if (max_uploads - used_slots > 0)
		/* Again no!. We are not out of upload slots yet. So there is no reason
		 * to let it continue now */
		return FALSE;

	if (parq_upload_continue(parq_ul, used_slots - 1)) {
		if (u->status == GTA_UL_QUEUED)
			u->status = GTA_UL_SENDING;

		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * @return If the download may continue, TRUE is returned. FALSE otherwise
 * (which probably means the upload is queued).
 */
gboolean
parq_upload_request(gnutella_upload_t *u, guint used_slots)
{
	gpointer handle = u->parq_opaque;
	struct parq_ul_queued *parq_ul = handle_to_queued(handle);
	time_t now = tm_time();
	time_t org_retry = parq_ul->retry;
	guint avg_bps;

	g_assert(u != NULL);

	parq_ul->chunk_size = u->skip > u->end ? 0 : u->end - u->skip + 1;
	parq_ul->updated = now;
	parq_ul->retry = now + parq_ul_calc_retry(parq_ul);

	g_assert(parq_ul->retry >= now);

	if (parq_optimistic) {
		avg_bps = bsched_avg_bps(bsched_bws_out());
		avg_bps = MAX(1, avg_bps);

		/* If the chunk sizes are really small, expire them sooner */
		parq_ul->expire = parq_ul->retry +
			parq_ul->chunk_size / avg_bps * max_uploads;
		parq_ul->expire = MIN(MIN_LIFE_TIME + parq_ul->retry, parq_ul->expire);
	} else
		parq_ul->expire = MIN_LIFE_TIME + parq_ul->retry;

	if (parq_debug > 1)
		g_message("[PARQ UL] Request for \"%s\" from %s <%s>: "
			"chunk=%lu, now=%d, retry=%d, expire=%d, quick=%s, has_slot=%s, "
			"uploaded=%lu",
			u->name, host_addr_to_string(u->addr),
			upload_vendor_str(u),
			(gulong) parq_ul->chunk_size, (gint) now, (gint) parq_ul->retry,
			(gint) parq_ul->expire, parq_ul->quick ? "y" : "n",
			parq_ul->has_slot ? "y" : "n", (gulong) parq_ul->uploaded_size);

	/*
	 * Make sure they did not retry the request too soon.
	 * This check is naturally skipped for follow-up requests.
	 */

	if (
		!parq_ul->has_slot &&		/* Not a follow-up request */
		org_retry > now &&
		!(
			(parq_ul->flags & PARQ_UL_QUEUE_SENT) ||
			u->status == GTA_UL_QUEUE_WAITING
		)
	) {
		/*
		 * Bad bad client, re-requested within the Retry-After interval.
		 * we are not going to allow this download. Whether it could get an
		 * upload slot or not. Neither are we going to active queue it.
		 */
		if (parq_debug) g_warning("[PARQ UL] "
			"host %s (%s) re-requested \"%s\" too soon (%d secs early)",
			host_addr_port_to_string(u->socket->addr, u->socket->port),
			upload_vendor_str(u),
			u->name, (gint) (org_retry - now));

		if (parq_ul->ban_timeout > now &&
			parq_ban_bad_maxcountwait != 0)
			parq_ul->ban_countwait++;
		
		if (parq_ul->ban_timeout > now &&
			parq_ul->ban_countwait >= parq_ban_bad_maxcountwait) {
			/*
			 * Bye bye, the client did it again, and is removed from the PARQ
		 	 * queue now.
			 */

			if (parq_debug) g_warning(
				"[PARQ UL] "
				"punishing %s (%s) for re-requesting \"%s\" %d secs early",
				host_addr_port_to_string(u->socket->addr, u->socket->port),
				upload_vendor_str(u),
				u->name, (gint) (org_retry - now));

			parq_add_banned_source(u->addr, parq_ul->retry - now);
			parq_upload_force_remove(u);
			return FALSE;
		}

		parq_ul->ban_timeout = now + parq_upload_ban_window;
		return FALSE;
	}

	/*
	 * If we sent a QUEUE message and we're getting a reply, reset the
	 * amount of QUEUE messages sent and clear the flag.
	 */

	if (parq_ul->flags & PARQ_UL_QUEUE_SENT) {
		parq_ul->queue_sent = 0;
		parq_ul->flags &= ~PARQ_UL_QUEUE_SENT;
	}

	/*
	 * Client was already downloading a segment, segment was finished and
	 * just did a follow up request.  However, if the slot was granted
	 * for a quick upload, and the amount requested is too large now,
	 * we cannot allow it to continue.
	 */

	if (parq_ul->has_slot) {
		if (!parq_ul->quick || parq_upload_quick_continue(parq_ul, used_slots))
			return TRUE;
		if (parq_debug)
			g_message("[PARQ UL] Fully checking quick upload slot");
		/* FALL THROUGH */
	}

	parq_ul->quick = FALSE;		/* Doing full "continue" checks now */

	/*
	 * Check whether the current upload is allowed to get an upload slot. If so
	 * move other queued items after the current item up one position in the
	 * queue
	 */

	if (parq_upload_continue(parq_ul, used_slots))
		return TRUE;

	if (parq_ul->has_slot) {
		parq_ul->by_addr->uploading--;
		parq_ul->queue->active_uploads--;
		parq_ul->has_slot = FALSE;
	}

	/* Don't allow more than 1 active queued upload per ip */
	if (parq_ul->by_addr->active_queued == 0 || parq_ul->active_queued) {

		/* Active queue requests which are either a push request and at a
		 * reasonable position. Or if the request is at a position which
		 * might actually get an upload slot soon
		 */
		if (
			(u->push &&
			  parq_ul->relative_position <= parq_upload_active_size) ||
			  parq_ul->relative_position <= max_uploads + 2
		) {
			if (parq_ul->minor > 0 || parq_ul->major > 0) {
				if (!parq_ul->active_queued) {
					if (parq_ul->by_addr->active_queued == 0) {
						u->status = GTA_UL_QUEUED;

						parq_ul->active_queued = TRUE;
						parq_ul->by_addr->active_queued++;
					}
				} else {
						u->status = GTA_UL_QUEUED;
				}
			}
		}
	}

	g_assert(parq_ul->by_addr->active_queued <= 1);

	u->parq_status = TRUE;		/* XXX would violate encapsulation */
	return FALSE;
}

/**
 * Mark an upload as really being active instead of just being queued.
 */
void
parq_upload_busy(gnutella_upload_t *u, gpointer handle)
{
	struct parq_ul_queued *parq_ul = handle_to_queued(handle);

	g_assert(parq_ul != NULL);

	if (parq_debug > 2) {
		g_message("PARQ UL: Upload %d[%d] is busy",
		  	  parq_ul->position, parq_ul->relative_position);
	}

	u->parq_status = FALSE;			/* XXX -- get rid of `parq_status'? */

	if (parq_ul->has_slot)
		return;

	/* XXX Perhaps it is wise to update the parq_ul->remote_addr here.
	 * XXX However, we should also update the parq_by_addr and all related
	 * XXX uploads.
	 */

	g_assert(parq_ul->by_addr != NULL);
	g_assert(host_addr_equal(parq_ul->by_addr->addr, parq_ul->remote_addr));


	parq_ul->has_slot = TRUE;
	parq_ul->had_slot = TRUE;
	parq_ul->queue->active_uploads++;
	parq_ul->by_addr->uploading++;
}

void
parq_upload_add(gnutella_upload_t *unused_u)
{
	/*
	 * Cosmetic. Not used at the moment. gnutella_upload_t structure probably
	 * isn't complete yet at this moment
	 */
	(void) unused_u;
}

void
parq_upload_force_remove(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = parq_upload_find(u);

	if (parq_ul != NULL && !parq_upload_remove(u))
		parq_upload_free(parq_ul);
}

/**
 * Collect running stats about the completed / removed upload.
 */
void
parq_upload_collect_stats(const gnutella_upload_t *u)
{
	struct parq_ul_queued *uq;

	g_assert(u);

	/*
	 * Browse host requests have no PARQ data structures associated with them,
	 * so having a completed upload does not necessarily imply there is
	 * something to track at this point.
	 */

	if (!u->parq_opaque)
		return;

	/*
	 * Data is only expected to be sent when the upload had a slot
	 */

   	uq = parq_upload_find(u);
	g_assert(uq != NULL);
	g_assert(uq->has_slot || uq->had_slot || 0 == u->sent);

	uq->uploaded_size += u->sent;
}

/**
 * When an upload is removed this function should be called so parq
 * knows the current upload status of an upload.
 *
 * @return TRUE if the download was totally removed. And the associated memory
 * was cleared. FALSE if the parq structure still exists.
 */
gboolean
parq_upload_remove(gnutella_upload_t *u)
{
	gboolean return_result = FALSE; /* True if the upload was really removed
									   ie: Removed from memory */
	time_t now = tm_time();
	struct parq_ul_queued *parq_ul = NULL;

	g_assert(u != NULL);

	/*
	 * Avoid removing an upload which is being removed because we are returning
	 * a busy (503), in which case the upload got queued
	 */

	if (u->parq_status) {
		u->parq_status = FALSE;
		return FALSE;
	}

	parq_ul = parq_upload_find(u);

	/*
	 * If parq_ul = NULL, than the upload didn't get a slot in the PARQ,
	 * or it is the parent of a now cloned upload (see upload_clone()).
	 */

	if (parq_ul == NULL)
		return FALSE;

	parq_upload_collect_stats(u);

	/*
	 * If we're still in the GTA_UL_QUEUE_WAITING state, we did not get any
	 * HTTP request after sending the QUEUE callback.  However, if we sent
	 * a QUEUE request and went further, reset the amount of refused QUEUE.
	 *		--RAM, 17/05/2003
	 */

	if (parq_debug > 2 && (parq_ul->flags & PARQ_UL_QUEUE_SENT))
		g_message("PARQ UL Q %d/%d: "
			"QUEUE #%d sent [refused=%d], u->status = %d",
			g_list_position(ul_parqs,
				g_list_find(ul_parqs, parq_ul->queue)) + 1,
			g_list_length(ul_parqs),
			parq_ul->queue_sent, parq_ul->queue_refused, u->status);

	if (u->status == GTA_UL_QUEUE_WAITING)
		parq_ul->queue_refused++;
	else if (parq_ul->flags & PARQ_UL_QUEUE_SENT)
		parq_ul->queue_refused = 0;

	parq_ul->flags &= ~PARQ_UL_QUEUE_SENT;

	if (parq_ul->has_slot && u->keep_alive && UPLOAD_WAITING_FOLLOWUP(u)) {
		if (parq_debug) g_message(
			"**** PARQ UL Q %d/%d: Not removed, waiting for new request",
			g_list_position(ul_parqs,
				g_list_find(ul_parqs, parq_ul->queue)) + 1,
			g_list_length(ul_parqs));
		return FALSE;
	}

	/*
	 * Reset "quick slot" indication since the upload is moved back
	 * to the queue.
	 */

	parq_ul->quick = FALSE;

	/*
	 * When the upload was actively queued, the last_update timestamp was
	 * set to somewhere in the feature to avoid early removal. However, now we
	 * do want to remove the upload.
	 */
	if (u->status == GTA_UL_QUEUED && u->last_update > now) {
		u->last_update = parq_ul->updated;
	}

	if (u->status == GTA_UL_QUEUED) {
		parq_ul->by_addr->active_queued--;
		g_assert(parq_ul->by_addr->active_queued >= 0);
	}

	parq_ul->active_queued = FALSE;

	if (parq_debug > 3)
		g_message("PARQ UL Q %d/%d: Upload removed",
			g_list_position(ul_parqs,
				g_list_find(ul_parqs, parq_ul->queue)) + 1,
			g_list_length(ul_parqs));

	if (parq_ul->has_slot) {
		GList *lnext = NULL;

		if (parq_debug > 2)
			g_message("PARQ UL: Freed an upload slot");

		g_assert(parq_ul->by_addr != NULL);
		g_assert(parq_ul->by_addr->uploading > 0);
		g_assert(host_addr_equal(parq_ul->by_addr->addr,parq_ul->remote_addr));

		parq_ul->by_addr->uploading--;
		parq_ul->queue->active_uploads--;

		/* Tell next waiting upload that a slot is available, using QUEUE */
		for (lnext = g_list_first(parq_ul->queue->by_rel_pos); lnext != NULL;
			  lnext = g_list_next(lnext)) {
				struct parq_ul_queued *parq_ul_next = lnext->data;

			if (!parq_ul_next->has_slot) {
				g_assert(parq_ul_next->queue->active <= 1);
				if (!(parq_ul_next->flags & (PARQ_UL_QUEUE|PARQ_UL_NOQUEUE)))
					parq_upload_register_send_queue(parq_ul_next);
				break;
			}
		}
	}

	g_assert(parq_ul->queue->active_uploads >= 0);

	if (u->status == GTA_UL_ABORTED &&
			parq_ul->disc_timeout > now && parq_ul->has_slot) {
		/* Client disconnects too often. This could block our upload
		 * slots. Sorry, but we are going to remove this upload */
		if (u->socket != NULL) {
			g_warning("[PARQ UL] "
				"Removing %s (%s) for too many disconnections \"%s\" "
				"%d secs early",
				host_addr_port_to_string(u->socket->addr, u->socket->port),
				upload_vendor_str(u),
				u->name, (gint) (parq_ul->disc_timeout - now));
		} else {
			g_warning("[PARQ UL] "
				"Removing (%s) for too many disconnections \"%s\" "
				"%d secs early",
				upload_vendor_str(u),
				u->name, (gint) (parq_ul->disc_timeout - now));
		}
		parq_upload_free(parq_ul);
		return_result = TRUE;

	} else {
		/*
		 * A client is not allowed to disconnect over and over again
		 * (ie data write error). Set the time for which a client
		 * should not disconnect
		 */
		if (parq_ul->has_slot)
			parq_ul->disc_timeout = now + (parq_upload_ban_window / 5);

		/* Disconnected upload is allowed to reconnect immediatly */
		parq_ul->has_slot = FALSE;
		parq_ul->retry = now;

		/*
		 * The upload slot expires rather soon to speed up uploading. This
		 * doesn't prevent a broken connection from reconnecting though, it is
		 * just not garanteed anymore that it will regain its upload slot
		 * immediatly
		 */
		parq_ul->expire = now + GUARDING_TIME;
	}

	return return_result;
}

/**
 * Adds X-Queued status in the HTTP reply header for a queued upload.
 *
 * @param `buf'		is the start of the buffer where the headers are to
 *					be added.
 * @param `retval'	contains the length of the buffer initially, and is
 *					filled with the amount of data written.
 * @param `arg'		no brief description.
 * @param `flags'	no brief description.
 *
 * @attention
 * NB: Adds a Retry-After field for servents that will not understand PARQ,
 * to make sure they do not re-request too soon.
 */
void
parq_upload_add_header(gchar *buf, gint *retval, gpointer arg, guint32 flags)
{
	gint rw = 0;
	gint length = *retval;
	time_t now = tm_time();
	struct upload_http_cb *a = arg;
	gboolean small_reply = (flags & HTTP_CBF_SMALL_REPLY);

	g_assert(buf != NULL);
	g_assert(retval != NULL);
	g_assert(a->u != NULL);

	if (parq_upload_queued(a->u)) {
		struct parq_ul_queued *parq_ul = parq_upload_find(a->u);
		guint min_poll, max_poll;

		min_poll = MAX(0, delta_time(parq_ul->retry, now));
		max_poll = MAX(0, delta_time(parq_ul->expire, now));

		if (
			parq_ul->major == 0 &&
			parq_ul->minor == 1 &&
			a->u->status == GTA_UL_QUEUED
		) {
			g_assert(length > 0);

			if (small_reply)
				rw = gm_snprintf(buf, length,
					"X-Queue: position=%d, pollMin=%u, pollMax=%u\r\n",
					parq_ul->relative_position, min_poll, max_poll);
			else
				rw = gm_snprintf(buf, length,
					"X-Queue: position=%d, length=%d, "
					"limit=%d, pollMin=%u, pollMax=%u\r\n",
					parq_ul->relative_position, parq_ul->queue->size,
					1, min_poll, max_poll);
		} else {
			g_assert(length > 0);

			if (small_reply)
				rw = gm_snprintf(buf, length,
					"X-Queue: %d.%d\r\n"
					"X-Queued: position=%d; ID=%s\r\n"
					"Retry-After: %d\r\n",
					PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR,
					parq_ul->relative_position,
					guid_hex_str(parq_ul->id),
					min_poll);
			else
				rw = gm_snprintf(buf, length,
					"X-Queue: %d.%d\r\n"
					"X-Queued: position=%d; ID=%s; length=%d;\r\n"
					"\tETA=%d; lifetime=%d\r\n"
					"Retry-After: %d\r\n",
					PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR,
					parq_ul->relative_position,
					guid_hex_str(parq_ul->id),
					parq_ul->queue->size,
					parq_ul->eta,
					max_poll,
					min_poll);

			/*
			 * If we filled all the buffer, try with a shorter string, bearing
			 * only the minimal amount of information.
			 */
			g_assert(length > 0);

			if (rw == length - 1 && buf[rw - 1] != '\n')
				rw = gm_snprintf(buf, length,
					"X-Queue: %d.%d\r\n"
					"X-Queued: ID=%s\r\n"
					"Retry-After: %d\r\n",
					PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR,
					guid_hex_str(parq_upload_lookup_id(a->u)),
					min_poll);

			parq_ul->flags |= PARQ_UL_ID_SENT;
		}
	}

	g_assert(rw < length);

	*retval = rw;
}

/**
 * Adds X-Queued status in the HTTP reply header showing the queue ID
 * for an upload getting a slot.
 *
 * `buf' is the start of the buffer where the headers are to be added.
 * `retval' contains the length of the buffer initially, and is filled
 * with the amount of data written.
 */
void
parq_upload_add_header_id(gchar *buf, gint *retval, gpointer arg,
		guint32 unused_flags)
{
	size_t rw = 0;
	size_t length = *retval;
	struct upload_http_cb *a = arg;
	struct parq_ul_queued *parq_ul;

	(void) unused_flags;
	g_assert(buf != NULL);
	g_assert(retval != NULL);
	g_assert(length <= INT_MAX);
	g_assert(length > 0);
	g_assert(a->u != NULL);

	parq_ul = parq_upload_find(a->u);

	g_assert(a->u->status == GTA_UL_SENDING);
	g_assert(parq_ul != NULL);

	/*
	 * If they understand PARQ, we also give them a queue ID even
	 * when they get an upload slot.  This will allow safe resuming
	 * should the connection be broken while the upload is active.
	 *		--RAM, 17/05/2003
	 */

	if (parq_ul->major >= 1) {
		rw += gm_snprintf(buf, length,
			"X-Queue: %d.%d\r\n"
			"X-Queued: ID=%s\r\n",
			PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR,
			guid_hex_str(parq_upload_lookup_id(a->u)));

		parq_ul->flags |= PARQ_UL_ID_SENT;
	}

	g_assert(rw < length);

	*retval = rw;
}

/**
 * Determines whether the PARQ ID was already sent for an upload.
 */
gboolean
parq_ul_id_sent(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = parq_upload_find(u);

	return parq_ul != NULL && (parq_ul->flags & PARQ_UL_ID_SENT);
}

/**
 * @return the current queueing position of an upload. Returns a value of
 * (guint) -1 if not found.
 */
guint
parq_upload_lookup_position(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;

	g_assert(u != NULL);

	parq_ul = parq_upload_find(u);

	if (parq_ul != NULL) {
		return parq_ul->relative_position;
	} else {
		return (guint) -1;
	}
}

/**
 * @return the current ID of the upload.
 */
const gchar *
parq_upload_lookup_id(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;

	g_assert(u != NULL);

	parq_ul = parq_upload_find(u);
	return parq_ul ? parq_ul->id : NULL;
}

/**
 * @return the Estimated Time of Arrival for an upload slot for a given upload.
 */
guint
parq_upload_lookup_eta(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul;

	parq_ul = parq_upload_find(u);

	/* If parq_ul == NULL the current upload isn't queued and ETA is unknown */
	if (parq_ul != NULL)
		return parq_ul->eta;
	else
		return (guint) -1;
}

/**
 * @return the current upload queue size of alive uploads.
 */
guint
parq_upload_lookup_size(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;

	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */

	parq_ul = parq_upload_find(u);

	if (parq_ul != NULL) {
		g_assert(parq_ul->queue != NULL);

		return parq_ul->queue->alive;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return the lifetime of a queued upload.
 */
time_t
parq_upload_lookup_lifetime(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;

	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */

	parq_ul = parq_upload_find(u);

	if (parq_ul != NULL) {
		return parq_ul->expire;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return the time_t at which the next retry is expected.
 */
time_t
parq_upload_lookup_retry(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;

	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */

	parq_ul = parq_upload_find(u);

	if (parq_ul != NULL) {
		return parq_ul->retry;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return the queue number the current upload is queued in.
 */
guint
parq_upload_lookup_queue_no(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;

	parq_ul = parq_upload_find(u);

	if (parq_ul != NULL) {
		return g_list_position(ul_parqs,
			  g_list_find(ul_parqs, parq_ul->queue)) + 1;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return TRUE if the upload was allowed quickly by PARQ.
 */
gboolean
parq_upload_lookup_quick(const gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = parq_upload_find(u);

	if (parq_ul != NULL)
		return parq_ul->quick;

	return FALSE;
}

/**
 * Updates the relative position of all queued after the given queued
 * item.
 */
static void
parq_upload_update_relative_position(struct parq_ul_queued *cur_parq_ul)
{
	GList *l = NULL;
	guint rel_pos = cur_parq_ul->relative_position;

	g_assert(cur_parq_ul != NULL);
	g_assert(cur_parq_ul->queue != NULL);
	g_assert(cur_parq_ul->queue->by_position != NULL);
	g_assert(cur_parq_ul->queue->size > 0);
	g_assert(rel_pos > 0);

	l = g_list_find(cur_parq_ul->queue->by_position, cur_parq_ul);

	if (cur_parq_ul->is_alive)
		rel_pos++;

	for (l = g_list_next(l); l; l = g_list_next(l)) {
		struct parq_ul_queued *parq_ul = l->data;

		g_assert(parq_ul != NULL);

		parq_ul->relative_position = rel_pos;

		if (parq_ul->is_alive)
			rel_pos++;

		g_assert(parq_ul->relative_position > 0);
	}
}

/**
 * Decreases the position of all queued items after the given queued item.
 */
static void
parq_upload_decrease_all_after(struct parq_ul_queued *cur_parq_ul)
{
	GList *l;
	gint pos_cnt = 0;	/* Used for assertion */

	g_assert(cur_parq_ul != NULL);
	g_assert(cur_parq_ul->queue != NULL);
	g_assert(cur_parq_ul->queue->by_position != NULL);
	g_assert(cur_parq_ul->queue->size > 0);

	l = g_list_find(cur_parq_ul->queue->by_position, cur_parq_ul);
	pos_cnt = ((struct parq_ul_queued *) l->data)->position;

	l = g_list_next(l);	/* Decrease _after_ current parq */

	/*
	 * Cycle through list and decrease all positions by one. Position should
	 * never reach 0 which would mean the queued item is currently uploading
	 */
	for (;	l; l = g_list_next(l)) {
		struct parq_ul_queued *parq_ul = l->data;

		g_assert(parq_ul != NULL);
		parq_ul->position--;

		g_assert((gint) parq_ul->position == pos_cnt);

		pos_cnt++;
		g_assert(parq_ul->position > 0);
	}
}

/**
 * Possibly register the upload in the list for deferred QUEUE sending.
 */
static void
parq_upload_register_send_queue(struct parq_ul_queued *parq_ul)
{
	g_assert(!(parq_ul->flags & PARQ_UL_QUEUE));

	/* No known connect back port / ip */
	if (parq_ul->port == 0 || !is_host_addr(parq_ul->addr)) {
		if (parq_debug > 2) {
			g_message("PARQ UL Q %d/%d (%3d[%3d]/%3d): "
				"No port to send QUEUE: %s '%s'",
				  g_list_position(ul_parqs,
				  	g_list_find(ul_parqs, parq_ul->queue)) + 1,
				  	g_list_length(ul_parqs),
				  parq_ul->position,
				  parq_ul->relative_position,
				  parq_ul->queue->size,
				  host_addr_to_string(parq_ul->remote_addr),
				  parq_ul->name
			);
		}
		parq_ul->flags |= PARQ_UL_NOQUEUE;
		return;
	}

	ul_parq_queue = g_list_append(ul_parq_queue, parq_ul);
	parq_ul->flags |= PARQ_UL_QUEUE;
}

/**
 * Sends a QUEUE to a parq enabled client.
 */
static void
parq_upload_send_queue(struct parq_ul_queued *parq_ul)
{
	struct gnutella_socket *s;
	gnutella_upload_t *u;
	time_t now = tm_time();

	g_assert(parq_ul->flags & PARQ_UL_QUEUE);

	parq_ul->last_queue_sent = now;		/* We tried... */
	parq_ul->queue_sent++;
	parq_ul->send_next_queue = 
		now + QUEUE_PERIOD * (1 + (parq_ul->queue_sent - 1) / 2.0);
	parq_ul->by_addr->last_queue_sent = now;

	if (parq_debug)
		g_message("PARQ UL Q %d/%d (%3d[%3d]/%3d): "
			"Sending QUEUE #%d to %s: '%s'",
			  g_list_position(ul_parqs,
			  g_list_find(ul_parqs, parq_ul->queue)) + 1,
			  g_list_length(ul_parqs),
			  parq_ul->position,
			  parq_ul->relative_position,
			  parq_ul->queue->size,
			  parq_ul->queue_sent,
			  host_addr_port_to_string(parq_ul->addr, parq_ul->port),
			  parq_ul->name);

	s = socket_connect(parq_ul->addr, parq_ul->port, SOCK_TYPE_UPLOAD, 0);

	if (!s) {
		g_warning("[PARQ UL] could not send QUEUE #%d to %s (can't connect)",
			parq_ul->queue_sent,
			host_addr_port_to_string(parq_ul->addr, parq_ul->port));
		return;
	}

	u = upload_create(s, TRUE);

	u->status = GTA_UL_QUEUE;
	u->name = atom_str_get(parq_ul->name);

	/* TODO: Create an PARQ pointer in the download structure, so we don't need
	 * to lookup the ID again, which we don't at the moment */
	parq_upload_update_addr_and_name(parq_ul, u);
	upload_fire_upload_info_changed(u);

	/* Verify created upload entry */
	g_assert(parq_upload_find(u) != NULL);
}

/**
 * 'Call back' connection was succesfull. So prepare to send headers
 */
void
parq_upload_send_queue_conf(gnutella_upload_t *u)
{
	gchar queue[MAX_LINE_SIZE];
	struct parq_ul_queued *parq_ul = NULL;
	struct gnutella_socket *s;
	size_t rw;
	ssize_t sent;
	time_t now = tm_time();

	g_assert(u);
	g_assert(u->status == GTA_UL_QUEUE);
	g_assert(u->name);

	parq_ul = parq_upload_find(u);

	if (parq_ul == NULL) {
		g_warning("[PARQ UL] Did the upload got removed?");
		return;
	}

	g_assert(parq_ul != NULL);

	parq_ul->by_addr->last_queue_connected = now;

	/*
	 * Send the QUEUE header.
	 */

	rw = gm_snprintf(queue, sizeof queue, "QUEUE %s %s\r\n",
			guid_hex_str(parq_ul->id),
			host_addr_port_to_string(listen_addr(), socket_listen_port()));

	s = u->socket;

	sent = bws_write(bsched_bws_out(), &s->wio, queue, rw);
	if ((ssize_t) -1 == sent) {
		g_warning("[PARQ UL] "
			"Unable to send back QUEUE for \"%s\" to %s: %s",
			  u->name, host_addr_port_to_string(s->addr, s->port),
			  g_strerror(errno));
	} else if ((size_t) sent < rw) {
		g_warning("[PARQ UL] "
			"Only sent %lu out of %lu bytes of QUEUE for \"%s\" to %s: %s",
			  (gulong) sent, (gulong) rw, u->name,
			  host_addr_port_to_string(s->addr, s->port), g_strerror(errno));
	} else if (parq_debug > 2) {
		g_message("PARQ UL: Sent #%d to %s: %s",
			  parq_ul->queue_sent, host_addr_port_to_string(s->addr, s->port),
			  queue);
	}

	if ((size_t) sent != rw) {
		upload_remove(u, "Unable to send QUEUE #%d", parq_ul->queue_sent);
		return;
	}

	parq_ul->flags |= PARQ_UL_QUEUE_SENT;		/* We sent the QUEUE message */

	/*
	 * We're now expecting HTTP headers on the connection we've made.
	 */
	expect_http_header(u, GTA_UL_QUEUE_WAITING);
}

/**
 * Saves an individual queued upload to disc.
 *
 * This is the callback function used by g_list_foreach() in function
 * parq_upload_save_queue().
 */
static inline void
parq_store(gpointer data, gpointer file_ptr)
{
	FILE *f = file_ptr;
	time_t now = tm_time();
	struct parq_ul_queued *parq_ul = data;
	gchar snq_buf[TIMESTAMP_BUF_LEN];
	gchar enter_buf[TIMESTAMP_BUF_LEN];
	gint expire;

	if (parq_ul->had_slot && !parq_ul->has_slot)
		/* We are not saving uploads which already finished an upload */
		return;

	expire = delta_time(parq_ul->expire, now);
	if (expire <= 0)
		return;

	g_assert(NULL != f);
	if (parq_debug > 5)
		g_message("PARQ UL Q %d/%d (%3d[%3d]/%3d): Saving ID: '%s' - %s '%s'",
			  g_list_position(ul_parqs,
				  g_list_find(ul_parqs, parq_ul->queue)) + 1,
			  g_list_length(ul_parqs),
			  parq_ul->position,
			  parq_ul->relative_position,
			  parq_ul->queue->size,
			  guid_hex_str(parq_ul->id),
			  host_addr_to_string(parq_ul->remote_addr),
			  parq_ul->name);

	timestamp_to_string_buf(parq_ul->enter, enter_buf, sizeof enter_buf);
	timestamp_to_string_buf(parq_ul->send_next_queue, snq_buf, sizeof snq_buf);
	
	/*
	 * Save all needed parq information. The ip and port information gathered
	 * from X-Node is saved as XIP and XPORT
	 * The lifetime is saved as a relative value.
	 */
	fprintf(f,
		  "QUEUE: %d\n"
		  "POS: %d\n"
		  "ENTERED: %s\n"
		  "EXPIRE: %d\n"
		  "ID: %s\n"
		  "SIZE: %s\n"
		  "IP: %s\n"
		  "QUEUESSENT: %d\n"
		  "SENDNEXTQUEUE: %s\n"
		  ,
		  g_list_position(ul_parqs, g_list_find(ul_parqs, parq_ul->queue)) + 1,
		  parq_ul->position,
		  enter_buf,
		  expire,
		  guid_hex_str(parq_ul->id),
		  uint64_to_string(parq_ul->file_size),
		  host_addr_to_string(parq_ul->remote_addr),
		  parq_ul->queue_sent,
		  snq_buf
		  );

	if (parq_ul->sha1) {
		fprintf(f, "SHA1: %s\n", sha1_base32(parq_ul->sha1));
	}
	if (is_host_addr(parq_ul->addr)) {
		fprintf(f,
			"XIP: %s\n"
			"XPORT: %u\n",
			host_addr_to_string(parq_ul->addr), (unsigned) parq_ul->port);
	}
	fprintf(f, "NAME: %s\n\n", parq_ul->name);
}

/**
 * Saves all the current queues and their items so it can be restored when the
 * client starts up again.
 */
void
parq_upload_save_queue(void)
{
	FILE *f;
	file_path_t fp;
	time_t now = tm_time();
	GList *queues;

	if (parq_debug > 3)
		g_message("PARQ UL: Trying to save all queue info");

	file_path_set(&fp, settings_config_dir(), file_parq_file);
	f = file_config_open_write("PARQ upload queue data", &fp);
	if (!f)
		return;

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n#\n", f);
	fprintf(f, "# Saved on %s\n", ctime(&now));

	for (
		queues = g_list_last(ul_parqs) ; queues != NULL; queues = queues->prev
	) {
		struct parq_ul_queue *queue = queues->data;

		G_LIST_FOREACH_WITH_DATA(queue->by_position, parq_store, f);
	}

	file_config_close(f, &fp);

	if (parq_debug > 3)
		g_message("PARQ UL: All saved");

}

typedef enum {
	PARQ_TAG_UNKNOWN = 0,
	PARQ_TAG_ENTERED,
	PARQ_TAG_EXPIRE,
	PARQ_TAG_ID,
	PARQ_TAG_IP,
	PARQ_TAG_NAME,
	PARQ_TAG_POS,
	PARQ_TAG_QUEUE,
	PARQ_TAG_SHA1,
	PARQ_TAG_SIZE,
	PARQ_TAG_XIP,
	PARQ_TAG_XPORT,
	PARQ_TAG_QUEUESSENT,
	PARQ_TAG_SENDNEXTQUEUE,

	NUM_PARQ_TAGS
} parq_tag_t;

static const struct parq_tag {
	parq_tag_t	tag;
	const gchar *str;
} parq_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define PARQ_TAG(x) { CAT2(PARQ_TAG_,x), #x }
	PARQ_TAG(ENTERED),
	PARQ_TAG(EXPIRE),
	PARQ_TAG(ID),
	PARQ_TAG(IP),
	PARQ_TAG(NAME),
	PARQ_TAG(POS),
	PARQ_TAG(QUEUE),
	PARQ_TAG(QUEUESSENT),
	PARQ_TAG(SENDNEXTQUEUE),
	PARQ_TAG(SHA1),
	PARQ_TAG(SIZE),
	PARQ_TAG(XIP),
	PARQ_TAG(XPORT),	

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef PARQ_TAG
};


/**
 */
static parq_tag_t
parq_string_to_tag(const gchar *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(parq_tag_map) == (NUM_PARQ_TAGS - 1));

#define GET_ITEM(i) (parq_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return parq_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const gchar *, s, G_N_ELEMENTS(parq_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return PARQ_TAG_UNKNOWN;
}


typedef struct {
	const gchar *sha1;
	filesize_t filesize;
	host_addr_t addr;
	host_addr_t x_addr;
	gint queue;
	gint pos;
	time_t entered;
	gint expire;
	gint xport;
	time_t send_next_queue;
	gint queue_sent;
	gchar name[1024];
	gchar id[GUID_RAW_SIZE];
} parq_entry_t;

/**
 * Loads the saved queue status back into memory.
 */
static void
parq_upload_load_queue(void)
{
	static const parq_entry_t zero_entry;
	parq_entry_t entry;
	FILE *f;
	file_path_t fp[1];
	gchar line[4096];
	gboolean next = FALSE;
	gnutella_upload_t u;
	struct parq_ul_queued *parq_ul;
	time_t now = tm_time();
	guint line_no = 0;
	guint64 v;
	gint error;
	const gchar *endptr;
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_PARQ_TAGS)];

	file_path_set(fp, settings_config_dir(), file_parq_file);
	f = file_config_open_read("PARQ upload queue data", fp, G_N_ELEMENTS(fp));
	if (!f)
		return;

	if (parq_debug)
		g_warning("[PARQ UL] Loading queue information");

	/* Reset state */
	entry = zero_entry;
	bit_array_clear_range(tag_used, 0, (guint) NUM_PARQ_TAGS - 1);

	while (fgets(line, sizeof(line), f)) {
		const gchar *tag_name, *value;
		gchar *colon, *nl;
		gboolean damaged;
		parq_tag_t tag;

		line_no++;

		damaged = FALSE;
		nl = strchr(line, '\n');
		if (!nl) {
			/*
			 * If the line is too long or unterminated the file is either
			 * corrupt or was manually edited without respecting the
			 * exact format. If we continued, we would read from the
			 * middle of a line which could be the filename or ID.
			 */
			g_warning("parq_upload_load_queue(): "
				"line too long or missing newline in line %u",
				line_no);
			break;
		}
		*nl = '\0';

		/* Skip comments and empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		colon = strchr(line, ':');
		if (!colon) {
			g_warning("parq_upload_load_queue(): missing colon in line %u",
				line_no);
			break;
		}
		*colon = '\0';
		tag_name = line;
		value = &colon[1];
		if (*value != ' ') {
			g_warning("parq_upload_load_queue(): "
				"missing space after colon in line %u",
				line_no);
			break;
		}
		value++;	/* skip blank after colon */

		tag = parq_string_to_tag(tag_name);
		g_assert((gint) tag >= 0 && tag < NUM_PARQ_TAGS);
		if (PARQ_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning("parq_upload_load_queue(): "
				"duplicate tag \"%s\" in entry in line %u",
				tag_name, line_no);
			break;
		}

		switch (tag) {
		case PARQ_TAG_IP:
		case PARQ_TAG_XIP:
			{
				host_addr_t addr;

				if (!string_to_host_addr(value, NULL, &addr)) {
					damaged = TRUE;
					g_warning("Not a valid IP address.");
				} else {
					switch (tag) {
					case PARQ_TAG_IP:
						entry.addr = addr;
						break;

					case PARQ_TAG_XIP:
						/* Ignore zero for backwards compatibility */
						entry.x_addr = addr;
						break;

					default:
						g_assert_not_reached();
					}
				}
			}
			break;

		case PARQ_TAG_QUEUE:
			v = parse_uint64(value, &endptr, 10, &error);
			damaged |= error != 0 || v > INT_MAX || *endptr != '\0';
			entry.queue = v;
			break;

		case PARQ_TAG_POS:
			v = parse_uint64(value, &endptr, 10, &error);
			damaged |= error != 0 || v > INT_MAX || *endptr != '\0';
			entry.pos = v;
			break;

		case PARQ_TAG_ENTERED:
			{
				time_t t;
				
				t = date2time(value, now);
				if (t != (time_t) -1) {
					entry.entered = t; 
				} else {
					/* For backwards-compatibility accept a raw integer value */
					v = parse_uint64(value, &endptr, 10, &error);
					damaged |= error != 0 || v > INT_MAX || *endptr != '\0';
					entry.entered = v;
				}
			}
			break;

		case PARQ_TAG_EXPIRE:
			v = parse_uint64(value, &endptr, 10, &error);
			damaged |= error != 0 || *endptr != '\0';
			entry.expire = v;
			break;

		case PARQ_TAG_XPORT:
			v = parse_uint64(value, &endptr, 10, &error);
			/* Ignore zero for backwards compatibility */
			damaged = error || v > 0xffff || *endptr != '\0';
			entry.xport = v;
			break;

		case PARQ_TAG_SIZE:
			v = parse_uint64(value, &endptr, 10, &error);
			damaged |= error != 0 ||
				(v > UINT_MAX && sizeof entry.filesize <= 4) ||
				*endptr != '\0';
			entry.filesize = v;
			break;

		case PARQ_TAG_ID:
			if (!hex_to_guid(value, entry.id)) {
				damaged = TRUE;
			}
			break;

		case PARQ_TAG_SHA1:
			{
				if (strlen(value) != SHA1_BASE32_SIZE) {
					damaged = TRUE;
					g_warning("Value has wrong length.");
				} else {
					const gchar *raw;

					raw = base32_sha1(value);
					if (!raw)
						damaged = TRUE;
					else
						entry.sha1 = atom_sha1_get(raw);
				}
			}
			break;
		case PARQ_TAG_QUEUESSENT:
			v = parse_uint64(value, &endptr, 10, &error);
			damaged |= error != 0 || v > INT_MAX || *endptr != '\0';
			entry.queue_sent = v;
			break;
		case PARQ_TAG_SENDNEXTQUEUE:
			{
				time_t t;
				
				t = date2time(value, now);
				damaged |= t == (time_t) -1;
				entry.send_next_queue = t; 
			}
			break;
		case PARQ_TAG_NAME:
			if (
				g_strlcpy(entry.name, value,
					sizeof entry.name) >= sizeof entry.name
			) {
				damaged = TRUE;
			} else {
				/* Expect next parq entry */
				next = TRUE;
			}
			break;

		case PARQ_TAG_UNKNOWN:
			damaged = TRUE;
			break;

		case NUM_PARQ_TAGS:
			g_assert_not_reached();
		}

		if (damaged) {
			g_warning("Damaged PARQ entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				line_no, tag_name, value);
			break;
		}

		if (next) {
			next = FALSE;

			g_assert(!damaged);

			/* Fill a fake upload structure */
			memset(&u, 0, sizeof u);
			u.file_size = entry.filesize;
			u.name = entry.name;
			u.addr = entry.addr;

			g_assert(u.name != NULL);

			parq_ul = parq_upload_create(&u);

			g_assert(parq_ul != NULL);

			parq_ul->enter = entry.entered;
			parq_ul->expire = time_advance(now, entry.expire);
			parq_ul->addr = entry.x_addr;
			parq_ul->port = entry.xport;
			parq_ul->sha1 = entry.sha1;
			parq_ul->send_next_queue = entry.send_next_queue;
			parq_ul->queue_sent = entry.queue_sent;

			/* During parq_upload_create already created an ID for us */
			g_hash_table_remove(ul_all_parq_by_id, parq_ul->id);

			STATIC_ASSERT(sizeof entry.id == sizeof parq_ul->id);
			memcpy(parq_ul->id, entry.id, sizeof parq_ul->id);
			g_hash_table_insert(ul_all_parq_by_id, parq_ul->id, parq_ul);

			if (parq_debug > 2)
				g_message("PARQ UL Q %d/%d (%3d[%3d]/%3d) ETA: %s "
					"Restored: %s '%s'",
					g_list_position(ul_parqs,
						g_list_find(ul_parqs, parq_ul->queue)) + 1,
					g_list_length(ul_parqs),
					parq_ul->position,
				 	parq_ul->relative_position,
					parq_ul->queue->size,
					short_time(parq_upload_lookup_eta(&u)),
					host_addr_to_string(parq_ul->remote_addr),
					parq_ul->name);

			if (max_uploads > 0)
				parq_upload_register_send_queue(parq_ul);

			/* Reset state */
			entry = zero_entry;
			bit_array_clear_range(tag_used, 0, (guint) NUM_PARQ_TAGS - 1);
		}
	}

	fclose(f);
}

/**
 * Adds an ip to the parq ban list.
 *
 * This list is used to deny connections from such a host. Sources will
 * only make it in this list when they ignore our delay Retry-After header
 * twice.
 */
void
parq_add_banned_source(const host_addr_t addr, time_t delay)
{
	time_t now = tm_time();
	struct parq_banned *banned = NULL;

	g_assert(ht_banned_source != NULL);

	banned = g_hash_table_lookup(ht_banned_source, &addr);
	if (banned == NULL) {
		/* Host not yet banned yet, good */
		banned = walloc0(sizeof *banned);
		banned->addr = addr;

		g_hash_table_insert(ht_banned_source, &banned->addr, banned);
		parq_banned_sources = g_list_append(parq_banned_sources, banned);
	}

	g_assert(banned != NULL);
	g_assert(host_addr_equal(banned->addr, addr));

	/* Update timestamp */
	banned->added = now;
	if (banned->expire < delay + now) {
		banned->expire = delay + now;
	}
}

/**
 * Removes a banned ip from the parq banned list.
 */
void
parq_del_banned_source(const host_addr_t addr)
{
	struct parq_banned *banned = NULL;

	g_assert(ht_banned_source != NULL);
	g_assert(parq_banned_sources != NULL);

	banned = g_hash_table_lookup(ht_banned_source, &addr);

	g_assert(banned != NULL);
	g_assert(host_addr_equal(banned->addr, addr));

	g_hash_table_remove(ht_banned_source, &addr);
	parq_banned_sources = g_list_remove(parq_banned_sources, banned);

	wfree(banned, sizeof *banned);
	banned = NULL;
}

/**
 * @return expiration timestamp if source is banned, or 0 if it isn't banned.
 */
time_t
parq_banned_source_expire(const host_addr_t addr)
{
	const struct parq_banned *banned;

	g_assert(ht_banned_source != NULL);

	banned = g_hash_table_lookup(ht_banned_source, &addr);

	return banned ? banned->expire : 0;
}

/**
 * Determine if we are still sharing this file, so that PARQ can
 * determine if it makes sense to keep this file in the queue.
 *
 * @return FALSE if the file is no longer shared, or TRUE if the file
 * is shared or if we don't know, e.g. if the library is being
 * rebuilt.
 */
static gboolean
parq_still_sharing(struct parq_ul_queued *parq_ul)
{
	struct shared_file *sf;

	if (parq_ul->sha1) {
		sf = shared_file_by_sha1(parq_ul->sha1);
		if (NULL == sf) {
			if (parq_debug)
				g_message("[PARQ UL] We no longer share this file: "
					"SHA1=%s \"%s\"",
					sha1_base32(parq_ul->sha1), parq_ul->name);
			return FALSE;
		}
		/* Either we have the file or we are rebuilding */
	} else {
		/*
		 * Let's see if we can find the SHA1 for this file if there
		 * isn't one on record yet. We can search for it by name, but
		 * in that way we miss out on the partial files. This is not a
		 * big deal here, because the partials will become normal
		 * files over time, and new partials do have a SHA1 in the
		 * PARQ data structure.
		 */
		sf = shared_file_by_name(parq_ul->name);
		if (sf != SHARE_REBUILDING) {
			if (NULL != sf && sha1_hash_available(sf)) {
				parq_ul->sha1 = atom_sha1_get(shared_file_sha1(sf));
				g_message("[PARQ UL] Found SHA1=%s for \"%s\"",
					sha1_base32(parq_ul->sha1), parq_ul->name);
				return TRUE;
			} else {
				if (parq_debug)
					g_message("[PARQ UL] We no longer share this file \"%s\"",
						parq_ul->name);
				return FALSE;
			}
		}
	}

	/* Return TRUE by default because this is the safest condition */
	return TRUE;
}

/**
 * Initialises the upload queue for PARQ.
 */
void
parq_init(void)
{

#define bs_nop(x)	(x)

	BINARY_ARRAY_SORTED(parq_tag_map, struct parq_tag, str, strcmp, bs_nop);

#undef bs_nop

	header_features_add(FEATURES_UPLOADS,
		"queue", PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR);
	header_features_add(FEATURES_DOWNLOADS,
		"queue", PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR);

	ul_all_parq_by_addr_and_name = g_hash_table_new(g_str_hash, g_str_equal);
	ul_all_parq_by_addr = g_hash_table_new(host_addr_hash_func,
								host_addr_eq_func);
	ul_all_parq_by_id = g_hash_table_new(guid_hash, guid_eq);
	dl_all_parq_by_id = g_hash_table_new(g_str_hash, g_str_equal);

	ht_banned_source = g_hash_table_new(host_addr_hash_func, host_addr_eq_func);

	(void) parq_upload_new_queue();

	g_assert(ul_all_parq_by_addr_and_name != NULL);
	g_assert(ul_all_parq_by_id != NULL);
	g_assert(ul_all_parq_by_addr != NULL);
	g_assert(dl_all_parq_by_id != NULL);
	g_assert(ht_banned_source != NULL);

	parq_upload_load_queue();
}

/**
 * Saves any queueing information and frees all memory used by PARQ.
 */
void
parq_close(void)
{
	GList *dl, *queues;
	GSList *sl, *to_remove = NULL, *to_removeq = NULL;

	parq_shutdown = TRUE;

	parq_upload_save_queue();

	for (dl = parq_banned_sources ; dl != NULL; dl = g_list_next(dl)) {
		struct parq_banned *banned = dl->data;

		to_remove = g_slist_prepend(to_remove, banned);
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct parq_banned *banned = sl->data;

		parq_del_banned_source(banned->addr);
	}

	g_slist_free(to_remove);
	to_remove = NULL;

	/*
	 * First locate all queued items (dead or alive). And place them in the
	 * 'to be removed' list.
	 */
	for (queues = ul_parqs; queues != NULL; queues = queues->next) {
		struct parq_ul_queue *queue = queues->data;

		for (dl = queue->by_position; dl != NULL; dl = g_list_next(dl)) {
			struct parq_ul_queued *parq_ul = dl->data;

			if (parq_ul == NULL)
				break;

			parq_ul->by_addr->uploading = 0;

			to_remove = g_slist_prepend(to_remove, parq_ul);
		}

		to_removeq = g_slist_prepend(to_removeq, queue);
	}

	/* Free all memory used by queued items */
	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl))
		parq_upload_free(sl->data);

	g_slist_free(to_remove);
	to_remove = NULL;

	for (sl = to_removeq; sl != NULL; sl = g_slist_next(sl)) {
		struct parq_ul_queue *queue = sl->data;

		/*
		 * We didn't decrease the active_uploads counters when we were freeing
		 * we don't care about this information anymore anyway.
		 * Set the queue inactive to avoid an assertion
		 */
		queue->active_uploads = 0;
		queue->active = FALSE;
		parq_upload_free_queue(queue);
	}

	g_slist_free(to_removeq);
	to_removeq = NULL;

	g_hash_table_destroy(ul_all_parq_by_addr_and_name);
	g_hash_table_destroy(ul_all_parq_by_addr);
	g_hash_table_destroy(ul_all_parq_by_id);

	g_hash_table_destroy(ht_banned_source);
	g_list_free(parq_banned_sources);

}

/* vi: set ts=4 sw=4 cindent: */

