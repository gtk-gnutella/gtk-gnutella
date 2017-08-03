/*
 * Copyright (c) 2003-2005, Jeroen Asselman
 * Copyright (c) 2003-2005, 2011 Raphael Manfredi
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
 * @date 2003-2005
 * @author Raphael Manfredi
 * @date 2003-2005, 2011
 */

#include "common.h"

#include "parq.h"

#include "ban.h"
#include "ctl.h"
#include "dmesh.h"
#include "downloads.h"
#include "features.h"
#include "geo_ip.h"
#include "gnet_stats.h"
#include "guid.h"
#include "hostiles.h"
#include "hosts.h"
#include "http.h"
#include "ioheader.h"
#include "settings.h"
#include "share.h"
#include "sockets.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/core/main.h"			/* For debugging() */

#include "lib/aging.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/bit_array.h"
#include "lib/concat.h"
#include "lib/cq.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/getline.h"
#include "lib/halloc.h"
#include "lib/hashlist.h"
#include "lib/hevset.h"
#include "lib/hikset.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/parse.h"
#include "lib/plist.h"
#include "lib/pslist.h"
#include "lib/stats.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/tokenizer.h"
#include "lib/walloc.h"

#include "lib/override.h"			/* Must be the last header included */

#define PARQ_VERSION_MAJOR	1
#define PARQ_VERSION_MINOR	1		/**< Version 1.1 since GTKG 0.96.6 */

#define PARQ_RETRY_FROZEN	300		/**< Each 5 minutes for frozen uploads */
#define PARQ_RETRY_SAFETY	40		/**< 40 seconds before lifetime */
#define PARQ_TIMER_BY_POS	30		/**< 30 seconds for each queue position */
#define PARQ_MIN_POLL		10		/**< Minimum poll time */
#define GUARDING_TIME		45		/**< Time we keep a slot after disconnect */
#define MIN_LIFE_TIME		60		/**< Grace time past retry-after */
#define QUEUE_PERIOD		600		/**< Try to resend a queue every 10 min. */
#define QUEUE_DEAD_SCAN		60		/**< Scan the "dead" queue every 60 secs. */
#define QUEUE_SAVE_PERIOD	60		/**< Save queues every minute */
#define QUEUE_HOST_DELAY	12		/**< No more than 1 QUEUE per 12 seconds */
#define MAX_QUEUE			144		/**< Max amount of QUEUE we can send */
#define MAX_QUEUE_REFUSED	2		/**< Max QUEUE they can refuse in a row */

#define MAX_UPLOADS			100		/**< Avoid more than that many uploads */
#define MAX_UPLOAD_QSIZE	4000	/**< Size of the PARQ queue */
#define MIN_UPLOAD_ASLOT	10		/**< Queue up to that many slots ahead */
#define MIN_ALWAYS_QUEUE	5		/**< Try to actively queue first 5 slots */
#define STAT_POINTS			150		/**< Amount of stat points to keep */
#define STAT_MIN_POINTS		10		/**< Min points before analyzing data */

#define MEBI (1024 * 1024)
/*
 * File sizes in queues:
 *
 * 1 ul: 0 < q1 < oo
 * 2 ul: 0 < q2 <= 600 Mi < q1 < oo
 * 3 ul: 0 < q3 <= 300 Mi < q2 <= 600 Mi < q1 < oo
 * ...
 */
#define PARQ_UL_LARGE_SIZE (600 * MEBI)

static htable_t *dl_all_parq_by_id;

static uint parq_max_upload_size = MAX_UPLOAD_QSIZE;

/**
 * parq_upload_active_size is the maximum number of active upload slots
 * per queue.
 *
 * This limit will only be reached when all requests are QUEUE, push or
 * the number of upload slots is also large.
 */
static uint parq_upload_active_size = 20;

static uint parq_upload_ban_window = 600;
static const char file_parq_file[] = "parq";

static plist_t *ul_parqs;			/**< List of all queued uploads */
static int ul_parqs_cnt;			/**< Amount of queues */
static hash_list_t *ul_parq_queue;	/**< To whom we need to send a QUEUE */
static aging_table_t *ul_queue_sent;	/** Used as search table by IP addr */
static hikset_t *ul_all_parq_by_addr_and_name;
static hevset_t *ul_all_parq_by_addr;
static htable_t *ul_all_parq_by_id;
static cperiodic_t *parq_dead_timer_ev;
static cperiodic_t *parq_save_timer_ev;
static bool parq_closed;

/**
 * If enable_real_passive is TRUE, a dead upload is only marked dead,
 * if FALSE, a dead upload is really removed and cannot reclaim its
 * position
 */
static bool enable_real_passive = TRUE;

static hevset_t *ht_banned_source;
static plist_t *parq_banned_sources;

struct parq_banned {
	host_addr_t addr;		/* Embedded key */
	time_t added;
	time_t expire;
};

static bool parq_shutdown;
static time_t parq_start;					/**< Init time */
static uint64 parq_slots_removed = 0;		/**< Amount of slots removed */

enum parq_ul_queue_magic {
	PARQ_UL_QUEUE_MAGIC = 0x7dbab331
};

/**
 * Holds status of current queue.
 */
struct parq_ul_queue {
	enum parq_ul_queue_magic magic;
	plist_t *by_position;		/**< Queued items sorted on position. Newest is
								 added to the end. */
	hash_list_t *by_rel_pos;	/**< Queued items sorted by relative position */
	hash_list_t *by_date_dead;	/**< Dead items sorted on last update */
	statx_t *slot_stats;		/**< Slot kept-time statistics */
	int by_position_length;	/**< Number of items in "by_position" */

	int num;				/**< Queue number */
	int active_uploads;
	int active_queued_cnt;	/**< Number of actively queued entries */
	int alive;				/**< Amount of alive entries */
	int frozen;				/**< Subset of alive entries that are frozen */
	unsigned recompute:1;	/**< Flagged as requiring update of internal data */
	unsigned active:1;		/**< Set to false when the number of upload slots
								 was decreased but the queue still contained
								 queued items. This queue shall be removed when
								 all queued items are finished / removed. */
};

static inline void
parq_ul_queue_check(const struct parq_ul_queue * const q)
{
	g_assert(q != NULL);
	g_assert(PARQ_UL_QUEUE_MAGIC == q->magic);
}

struct parq_ul_queued_by_addr {
	int	uploading;		/**< Number of uploads uploading */
	int	total;			/**< Total queued items for this ip */
	int 	active_queued;	/**< Total actively queued items for this ip */
	int 	frozen;			/**< Total frozen items for this ip */
	host_addr_t addr;

	time_t	last_queue_sent;
	time_t	last_queue_failure;

	plist_t	*list;			/**< List or queued items for this ip */
};

enum parq_ul_magic {
	PARQ_UL_MAGIC = 0x6a3900a1
};

/**
 * Contains the queued upload.
 */
struct parq_ul_queued {
	enum parq_ul_magic magic;			/**< Magic number */
	uint32 flags;			/**< Operating flags */
	uint position;			/**< Current position in the queue */
	uint relative_position; /**< Relative position in the queue, if 'not alive'
								  uploads are taken into account */
	uint eta;				/**< Expected time in seconds till an upload slot is
							     reached, this is a relative timestamp */

	time_t expire;			/**< Time when the queue position will be lost */
	time_t retry;			/**< Time when the first retry-after is expected */
	time_t enter;			/**< Time upload entered parq */
	time_t updated;			/**< Time last upload request was sent */
	time_t ban_timeout;		/**< Time after which we won't kick out the upload
							     out of the queue when retry isn't obeyed */
	time_t disc_timeout;	/**< Time after which we allow the upload to be
							     disconnected again. */
	uint ban_countwait;		/**< Counter is increased everytime a client did
								 not obey the retry-after header, used to
								 ban a client. */

	time_t last_queue_sent;	/**< When we last sent the QUEUE */
	time_t send_next_queue;	/**< When to send the next QUEUE */
	time_t slot_granted;	/**< Time at which the upload slot was granted */
	uint32 queue_sent;		/**< Amount of QUEUE messages we tried to send */
	uint32 queue_refused;	/**< Amount of QUEUE messages refused remotely */

	struct guid id;			/**< PARQ identifier; GUID atom */

	char *addr_and_name;	/**< "IP name", used as key in hash table */
	const char *name;		/**< NB: points directly into `addr_and_name' */
	const struct sha1 *sha1;	/**< SHA1 digest for easy reference */
	host_addr_t remote_addr;	/**< IP address of the socket endpoint */

	filesize_t file_size;	/**< Needed to recalculate ETA */
	filesize_t chunk_size;	/**< Requested chunk size */
	filesize_t uploaded_size;	/**< Bytes previously uploaded */
	filesize_t downloaded;	/**< Their advertized downloaded amount */
	host_addr_t addr;		/**< Contact IP:port, as read from X-Node: */
	uint16 port;

	uint major;
	uint minor;

	struct parq_ul_queue *queue;	/**< In which queue this entry is listed */
	struct parq_ul_queued_by_addr *by_addr;

	struct upload *u;	/**< Internal ref to upload structure if available */

	unsigned quick:1;			/**< Slot granted for allowed quick upload */
	unsigned active_queued:1;	/**< Whether current upload actively queued */
	unsigned has_slot:1;		/**< Whether the items is currently uploading */
	unsigned had_slot:1;		/**< Whether we granted a slot to that entry */
	unsigned is_alive:1;		/**< Whether client is still requesting file */
	unsigned supports_parq:1;	/**< Is downloader PARQ-aware? */
};

static inline void
parq_ul_queued_check(const struct parq_ul_queued * const puq)
{
	g_assert(puq != NULL);
	g_assert(PARQ_UL_MAGIC == puq->magic);
}

/*
 * Flags for parq_ul_queued.
 */

enum {
	PARQ_UL_MARK		= 1 << 6,	/**< Mark for duplicate checks */
	PARQ_UL_SPECIAL		= 1 << 5,	/**< Special upload */
	PARQ_UL_FROZEN		= 1 << 4,	/**< Frozen entry */
	PARQ_UL_ID_SENT		= 1 << 3,	/**< We already sent an ID */
	PARQ_UL_QUEUE_SENT	= 1 << 2,	/**< QUEUE message sent */
	PARQ_UL_NOQUEUE		= 1 << 1,	/**< No valid IP:port, don't send QUEUE */
	PARQ_UL_QUEUE		= 1 << 0	/**< Scheduled for QUEUE sending */
};

/**
 * Contains the queued download status.
 */
struct parq_dl_queued {
	uint position;			/**< Current position in the queue */
	uint length;			/**< Current queue length */
	time_t eta;				/**< Estimated time till upload slot retrieved */
	uint lifetime;			/**< Max interval before loosing queue position */
	uint retry_delay;		/**< Interval between new attempt */
	char *id;				/**< PARQ Queue ID, +1 for trailing NUL */
};

/**
 * File descriptor availability status, for fd_avail_status().
 */
enum fd_avail_status {
	FD_AVAIL_GREEN = 0,		/**< We have enough fd to operate */
	FD_AVAIL_YELLOW = 1,	/**< Warning, we have to steal from banning fd */
	FD_AVAIL_RED = 2		/**< Critical, we ran out of fd */
};

/***
 ***  Generic non PARQ specific functions
 ***/

static enum fd_avail_status
fd_avail_status(void)
{
	if (GNET_PROPERTY(file_descriptor_runout))
		return FD_AVAIL_RED;
	else if (GNET_PROPERTY(file_descriptor_shortage))
		return FD_AVAIL_YELLOW;
	else
		return FD_AVAIL_GREEN;
}

static const char *
fd_avail_status_string(enum fd_avail_status s)
{
	switch (s) {
	case FD_AVAIL_GREEN:	return "green";
	case FD_AVAIL_YELLOW:	return "yellow";
	case FD_AVAIL_RED:		return "red";
	}
	return "UNKNOWN";
}

/**
 * Get header version.
 *
 * Extract the version from a given header. EG:
 * X-Queue: 1.0
 * major=1 minor=0
 *
 * @param header is a pointer to the header string that will be parsed for
 *        the version number
 * @param major is a pointer to a int in which the major version number will
 *        be returned on success.
 * @param minor is a pointer to a int in which the minor version number will
 *        be returned on success.
 *
 * @return a boolean which is true when parsing of the header version was
 * successful.
 */
static bool
get_header_version(char const * const header, uint *major, uint *minor)
{
	return 0 == parse_major_minor(header, NULL, major, minor);
}

static const char *
parq_get_x_queue_header(void)
{
	STATIC_ASSERT(PARQ_VERSION_MAJOR == 1);
	STATIC_ASSERT(PARQ_VERSION_MINOR == 1);
	return "X-Queue: 1.1";
}

static const char *
parq_get_x_queue_legacy_header(void)
{
	return "X-Queue: 0.1";
}

/**
 * Get header value.
 *
 * Retrieves a value from a header line. If possible the length (in chars)
 * is returned for that value.
 *
 * @param s is a pointer to the header string that will be parsed.
 * @param attribute is the attribute which will be searched in the header string
 * @param length is a pointer to a size_t variable which will contain the
 *		  length of the header value, if parsing was successful.
 *
 * @return a pointer in the s pointer indicating the start of the header value.
 */
static const char *
get_header_value(const char *const s,
	char const *const attribute, size_t *length)
{
	const char *header = s;
	char *end;
	bool found_right_attribute = FALSE;
	bool found_equal_sign = FALSE;

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
		char e;
		char b;
		char es;

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
				g_warning("%s() in %s: "
					"attribute '%s' has no value in string: %s",
					G_STRFUNC, _WHERE_, attribute, s);
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
 * Retrieves the PARQ ID associated with a download.
 *
 * @return a char pointer to the ID, or NULL if no ID is available.
 */
const char *
get_parq_dl_id(const struct download *d)
{
	download_check(d);
	return d->parq_dl ? d->parq_dl->id : NULL;
}

/**
 * Retrieves the remote queued position associated with a download.
 *
 * @returns the remote queued position or 0 if download is not queued or
 * queuing status is unknown
 */
int
get_parq_dl_position(const struct download *d)
{
	download_check(d);
	return d->parq_dl ? d->parq_dl->position : 0;
}

/**
 * Retrieves the remote queue size associated with a download.
 *
 * @return the remote queue size or 0 if download is not queued or queueing
 * status is unknown.
 */
int
get_parq_dl_queue_length(const struct download *d)
{
	download_check(d);
	return d->parq_dl ? d->parq_dl->length : 0;
}

/**
 * Retrieves the estimated time of arival for a queued download.
 *
 * @return the relative eta or 0 if download is not queued or queuing status is
 * unknown.
 */
int
get_parq_dl_eta(const struct download *d)
{
	download_check(d);
	return d->parq_dl ? d->parq_dl->eta : 0;
}

/**
 * Retrieves the retry rate at which a queued download should retry.
 *
 * @return the retry rate or 0 if download is not queued or queueing status is
 * unknown.
 */
int
get_parq_dl_retry_delay(const struct download *d)
{
	download_check(d);
	return d->parq_dl ? d->parq_dl->retry_delay : 0;
}

/**
 * Whether the download is queued remotely or not.
 */
bool
parq_download_is_active_queued(const struct download *d)
{
	download_check(d);
	return d->parq_dl && d->parq_dl->position > 0 && d->keep_alive;
}

/**
 * Whether the download is queued remotely without keeping the connection or not
 */
bool
parq_download_is_passive_queued(const struct download *d)
{
	download_check(d);
	return d->parq_dl && d->parq_dl->position > 0 && !d->keep_alive;
}

/**
 * Switch PARQ downloading IDs if the position in the older download is more
 * interesting than the one in the newer one.
 */
static void
parq_download_switch(struct download *od, struct download *nd)
{
	struct parq_dl_queued *opd, *npd;

	download_check(od);
	download_check(nd);
	g_assert(od->server == nd->server);

	opd = od->parq_dl;

	if (NULL == opd->id)
		return;		/* Not a PARQ download */

	npd = nd->parq_dl;
	if (NULL == npd) {
		g_carp("%s(): switching between a PARQ download and a non-PARQ one: "
			"old was \"%s\", new is \"%s\" at %s",
			G_STRFUNC, download_basename(od), download_basename(nd),
			download_host_info(nd));
		return;
	}

	if (opd->position >= npd->position)
		return;

	/*
	 * Position in the old download is more interesting, switch the IDs.
	 */

	if (GNET_PROPERTY(parq_debug)) {
		g_debug("PARQ switching IDs between \"%s\" and \"%s\" at %s: "
			"old position %u lower than new %u",
			download_basename(od), download_basename(nd),
			download_host_info(nd), opd->position, npd->position);
	}

	od->parq_dl = npd;
	nd->parq_dl = opd;
}

/**
 * Active queued means we didn't close the http connection on a HTTP 503 busy
 * when the server supports queueing. So prepare the download structure
 * for a 'valid' segment. And re-request the segment.
 */
void
parq_download_retry_active_queued(struct download *d)
{
	fileinfo_t *fi;
	struct download *other = NULL;		/* Becomes non-NULL if we switch */
	bool prepared;

	download_check(d);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_ACTIVE_QUEUED);
	g_assert(d->parq_dl != NULL);
	g_assert(parq_download_is_active_queued(d));

	/*
	 * If the file was completed during our waiting, try to switch to another
	 * pending download on the same server, if any.
	 */

	fi = d->file_info;
	file_info_check(fi);

	if (FILE_INFO_COMPLETE(fi)) {
		other = download_pick_another_waiting(d);
		if (other != NULL) {
			download_switch(d, other, FALSE);
			/*
			 * Don't stop download, we may be still computing the SHA1 of
			 * the file and we need to keep the source around, just in case.
			 */
			download_queue(d,
				_("Switching to \"%s\""), download_basename(other));

			if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(parq_debug)) {
				g_debug("PARQ switched resource to %s -- completed %s on %s",
					download_basename(other),
					download_basename(d), download_host_info(d));
			}

			parq_download_switch(d, other);
			d = other;	/* Now processing the new download */
		}
	}

	prepared = NULL == other ?
		download_start_prepare_running(d) :		/* Was already running */
		download_start_prepare(d);				/* Was waiting */

	if (prepared) {
		struct gnutella_socket *s = d->socket;
		d->keep_alive = TRUE;			/* was reset in start_prepare_running */

		/* d->io_opaque could be NULL if we switched downloads above */
		if (d->io_opaque != NULL) {
			/* Will be re initialised in download_send_request */
			io_free(d->io_opaque);
			d->io_opaque = NULL;
		}

		/* s->getline could be NULL if we switched downloads above */
		getline_free_null(&s->getline);

		/* Resend request for download */
		download_send_request(d);
	}
}

/**
 * Convenience wrapper on top of parse_uint32().
 *
 * @return parsed integer (base 10), or 0 if none could be found.
 */
static uint
get_integer(const char *buf)
{
	const char *endptr;
	uint32 val;
	int error;

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
	if (d->parq_dl) {
		parq_dl_free(d);
	}
}

/**
 * Remove the memory used by the ID string, and removes it from
 * various lists
 */
static void
parq_dl_del_id(struct download *d)
{
	struct parq_dl_queued *parq_dl;

	download_check(d);
	parq_dl = d->parq_dl;

	g_assert(parq_dl != NULL);
	g_assert(parq_dl->id != NULL);

	htable_remove(dl_all_parq_by_id, parq_dl->id);
	HFREE_NULL(parq_dl->id);

	g_assert(parq_dl->id == NULL);	/* We don't expect an id here */
}


/**
 * Removes the queue information for a download from memory.
 */
void
parq_dl_free(struct download *d)
{
	struct parq_dl_queued *parq_dl;

	download_check(d);
	parq_dl = d->parq_dl;

	if (parq_dl->id != NULL)
		parq_dl_del_id(d);

	g_assert(parq_dl->id == NULL);

	WFREE(parq_dl);
	d->parq_dl = NULL;
}

/**
 * Creates a queue structure for a download.
 *
 * @return a parq_dl_queued pointer to the newly created structure.
 */
struct parq_dl_queued *
parq_dl_create(const struct download *d)
{
	struct parq_dl_queued *parq_dl;

	download_check(d);
	g_assert(d->parq_dl == NULL);

	WALLOC(parq_dl);
	parq_dl->id = NULL;		/* Can't allocate yet, ID size isn't fixed */
	parq_dl->position = 0;

	return parq_dl;
}

/**
 * Assigns an parq ID to a download, and places them in various lists for lookup
 */
void
parq_dl_add_id(struct download *d, const char *new_id)
{
	struct parq_dl_queued *parq_dl;

	download_check(d);
	g_assert(new_id != NULL);
	g_assert(d->parq_dl != NULL);

	parq_dl = d->parq_dl;

	g_assert(parq_dl != NULL);
	g_assert(parq_dl->id == NULL);	/* We don't expect an id here */

	parq_dl->id = h_strdup(new_id);
	htable_insert(dl_all_parq_by_id, parq_dl->id, d);

	g_assert(parq_dl->id != NULL);
}

/**
 * Called from download_clone to reparent the PARQ ID from the parent `d'
 * to the cloned `cd'.
 */
void
parq_dl_reparent_id(struct download *d, struct download *cd)
{
	struct parq_dl_queued *parq_dl;

	download_check(d);
	download_check(cd);

	parq_dl = d->parq_dl;

	g_assert(parq_dl != NULL);
	g_assert(d->parq_dl == cd->parq_dl);	/* Cloned */

	/*
	 * Legacy queueing might not provide any ID.
	 */

	if (parq_dl->id != NULL) {
		/* Replace value */
		htable_insert(dl_all_parq_by_id, parq_dl->id, cd);
	}

	d->parq_dl = NULL;			/* No longer associated to `d' */
}

/**
 * Updates a parq id if needed.
 */
static void
parq_dl_update_id(struct download *d, const char *temp)
{
	download_check(d);
	g_assert(temp != NULL);

	if (d->parq_dl->id) {
		if (0 == strcmp(temp, d->parq_dl->id))
			return;

		parq_dl_del_id(d);
	}

	parq_dl_add_id(d, temp);
}

/**
 * Retrieve and parse queueing information.
 *
 * @param d			the download
 * @param header	parsed headers we got from d
 * @param code		HTTP status code of the reply
 *
 * @return TRUE if we parsed it OK, FALSE on error.
 */
bool
parq_download_parse_queue_status(struct download *d,
	header_t *header, uint code)
{
	struct parq_dl_queued *parq_dl = NULL;
	const char *buf;
	char *temp = NULL;
	const char *value = NULL;
	uint major, minor;
	size_t header_value_length;
	int retry;

	download_check(d);
	g_assert(dl_server_valid(d->server));
	g_assert(header != NULL);

	/*
	 * We cannot assume X-Features will be emitted each time.  Starting
	 * with 0.96.6, GTKG only emits it once per connection, at the first reply.
	 *
	 * Therefore, if we already have a known PARQ version support for the
	 * server, reuse it, and only look for X-Features and X-Queue if we
	 * don't know anything.
	 */

	major = d->server->parq_version.major;
	minor = d->server->parq_version.minor;

	if (major == 0 && minor == 0) {
		if (!header_get_feature("queue", header, &major, &minor)) {
			const char *queue = header_get(header, "X-Queue");

			if (queue && !get_header_version(queue, &major, &minor)) {
				/* Assume version 0.1 since we have the X-Queue header */
				major = 0;
				minor = 1;
			}
		}
		/* Paranoid -- force at least 1.0 if we see the "X-Queued" header */
		if (major < 1 && header_get(header, "X-Queued")) {
			major = 1;
			minor = 0;
		}
	}

	d->server->parq_version.major = major;
	d->server->parq_version.minor = minor;

	if (major == 0 && minor == 0)
		return FALSE;				/* No queueing supported */

	/*
	 * OK, server supports queueuing, but is this download being queued?
	 */

	switch (major) {
	case 0:				/* Active queueing */
		buf = header_get(header, "X-Queue");
		if (buf == NULL && 503 == code)
			return FALSE;
		break;
	case 1:				/* PARQ */
		buf = header_get(header, "X-Queued");
		if (buf == NULL && 503 == code) {
			g_warning("[PARQ DL] server %s advertised PARQ %d.%d but did not"
				" send X-Queued on HTTP 503",
				server_host_info(d->server), major, minor);
			if (GNET_PROPERTY(parq_debug)) {
				g_warning("[PARQ DL]: header dump:");
				header_dump(stderr, header, NULL);
			}
			return FALSE;
		}
		break;
	default:
		g_warning("[PARQ DL] unhandled queuing version %d.%d from %s <%s>",
			major, minor,
			host_addr_port_to_string(download_addr(d), download_port(d)),
			download_vendor_str(d));
		return FALSE;
	}

	/*
	 * If no queue header to parse at this point, then we're dealing with
	 * an HTTP status other than 503 and it's OK, we have no more work to do.
	 */

	if (NULL == buf) {
		g_assert(code != 503);
		return TRUE;			/* Did not have any queue info to parse */
	}

	if (d->parq_dl == NULL) {
		/* So this download has no parq structure yet, well create one! */
		d->parq_dl = parq_dl_create(d);
	}
	parq_dl = d->parq_dl;

	g_assert(parq_dl != NULL);

	switch (major) {
	case 0:				/* Active queueing */
		value = get_header_value(buf, "pollMin", NULL);
		parq_dl->retry_delay  = value == NULL ? 0 : get_integer(value);

		value = get_header_value(buf, "pollMax", NULL);
		parq_dl->lifetime  = value == NULL ? 0 : get_integer(value);
		break;
	case 1:				/* PARQ */
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
			temp = h_strndup(value, header_value_length);

			parq_dl_update_id(d, temp);

			HFREE_NULL(temp);
		}
		break;
	default:
		g_assert_not_reached();
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

	if (retry > (int) (parq_dl->lifetime - PARQ_RETRY_SAFETY))
		retry = parq_dl->lifetime - PARQ_RETRY_SAFETY;
	if (retry < (int) parq_dl->retry_delay)
		retry = parq_dl->retry_delay;

	if (GNET_PROPERTY(parq_debug))
		g_debug("file \"%s\" on %s queued "
			"(version: %d.%d, position %d out of %d,"
			" retry in %ds within [%d, %d])",
			download_basename(d), server_host_info(d->server),
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
 * Adds an:
 *
 *    - X-Queue: 1.0
 *    - X-Queued: position=x; ID=xxxxx
 *
 * to the HTTP GET request in the buffer "buf".
 */
void
parq_download_add_header(
	char *buf, size_t len, size_t *rw, struct download *d)
{
	bool has_ipv4 = FALSE;
	host_addr_t addr;
	uint16 port;

	g_assert(d != NULL);
	g_assert(rw != NULL);
	g_assert(UNSIGNED(len) <= INT_MAX);
	g_assert(UNSIGNED(*rw) <= INT_MAX);
	g_assert(len >= *rw);

	*rw += str_bprintf(&buf[*rw], len - *rw, "%s\r\n",
		(d->server->attrs & DLS_A_FAKE_G2) ?
			parq_get_x_queue_legacy_header() : parq_get_x_queue_header());

	/*
	 * Only add X-Queued header if server really supports X-Queue: 1.x. Don't
	 * add X-Queued if there is no ID available. This could be because it is
	 * a first request.
	 */

	if (d->server->parq_version.major == 1) {
		if (get_parq_dl_id(d) != NULL)
			*rw += str_bprintf(&buf[*rw], len - *rw,
				  	"X-Queued: position=%d; ID=%s\r\n",
				  	get_parq_dl_position(d),
				  	get_parq_dl_id(d));
	}

	/*
	 * Only send X-Node if not firewalled and the listen IP/port combination
	 * we're claiming is "valid".
	 */

	if (GNET_PROPERTY(is_firewalled) || (d->server->attrs & DLS_A_FAKE_G2))
		return;

	port = socket_listen_port();
	if (0 == port)
		return;

	addr = listen_addr();
	if (is_host_addr(addr)) {
		has_ipv4 = TRUE;
		*rw += str_bprintf(&buf[*rw], len - *rw,
		  	  "X-Node: %s\r\n",
			  host_addr_port_to_string(addr, port));
	}

	addr = listen_addr6();
	if (is_host_addr(addr)) {
		*rw += str_bprintf(&buf[*rw], len - *rw,
		  	  "%s%s\r\n",
			  has_ipv4 ? "X-Node-IPv6: " : "X-Node: ",
			  host_addr_port_to_string(addr, port));
	}
}

/**
 * PARQ enabled servers send a 'QUEUE' command when the lifetime of the download
 * (upload from the servers point of view) is about to expire, or if the
 * download has retrieved a download slot (upload slot from the servers point
 * of view). This function looksup the ID associated with the QUEUE command
 * and prepares the download to continue.
 */
void
parq_download_queue_ack(struct gnutella_socket *s)
{
	const char *queue;
	char *id;
	char *ip_str;
	struct download *dl;
	host_addr_t addr;
	uint16 port = 0;
	bool has_ip_port = TRUE;

	socket_tos_default(s);	/* Set proper Type of Service */

	g_assert(s != NULL);
	g_assert(s->getline);

	queue = getline_str(s->getline);

	gnet_stats_inc_general(GNR_QUEUE_CALLBACKS);

	if (GNET_PROPERTY(download_trace) & SOCK_TRACE_IN) {
		g_debug("----Got QUEUE from %s:\n", host_addr_to_string(s->addr));
		dump_string(stderr, queue, getline_length(s->getline), "----");
	}

	/*
	 * Ensure we can accept the incoming connection to perform an outgoing
	 * HTTP request, eventually.
	 */

	if (hostiles_is_bad(s->addr)) {
		if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(socket_debug)) {
			hostiles_flags_t flags = hostiles_check(s->addr);
			g_warning("discarding GIV string \"%s\" from hostile %s (%s)",
				queue, host_addr_to_string(s->addr),
				hostiles_flags_to_string(flags));
		}
		goto ignore;
	}

	if (ctl_limit(s->addr, CTL_D_OUTGOING)) {
		if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(ctl_debug)) {
			g_warning("CTL discarding QUEUE string \"%s\" from %s [%s]",
				queue, host_addr_to_string(s->addr), gip_country_cc(s->addr));
		}
		goto ignore;
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

	dl = htable_lookup(dl_all_parq_by_id, id);

	/*
	 * If we were unable to locate a download by this ID, try to elect
	 * another download from this host for which we don't have any PARQ
	 * information yet.
	 */

	if (dl == NULL) {
        if (GNET_PROPERTY(parq_debug)) {
            g_debug("[PARQ DL] could not locate QUEUE id '%s' from %s",
                id, host_addr_port_to_string(addr, port));
        }

		if (has_ip_port) {
			dl = download_find_waiting_unparq(addr, port);

			if (dl != NULL) {
                if (GNET_PROPERTY(parq_debug)) {
                    g_debug("[PARQ DL] elected '%s' from %s for QUEUE"
                        " id '%s'",
                        dl->file_name,
						host_addr_port_to_string(addr, port), id);
                }

				g_assert(dl->parq_dl == NULL);		/* unparq'ed */

				dl->parq_dl = parq_dl_create(dl);
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
			if (GNET_PROPERTY(parq_debug)) {
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
	 * Send the request on the connection the server opened.
	 *
	 * NB: if this is the initial QUEUE request we get after being relaunched,
	 * we won't have a valid queue position to send back, and 0 will be used.
	 */

	if (download_start_prepare(dl)) {
		download_attach_socket(dl, s);

		dl->last_update = tm_time();
		download_send_request(dl);		/* Resend request for download */
	}

	return;

ignore:
	gnet_stats_inc_general(GNR_QUEUE_DISCARDED);
	socket_free_null(&s);
}

/***
 ***  The following section contains upload queueing
 ***/

/**
 * Convert a handle to a `parq_ul_queued' structure.
 */
static inline struct parq_ul_queued *
handle_to_queued(struct parq_ul_queued *puq)
{
	parq_ul_queued_check(puq);

	return puq;
}

/**
 * Compute a statistically probable time used by an upload slot in the queue.
 *
 * @return probable slot time, or 0 if we cannot compute anything due to
 * too little data points.
 */
static uint
parq_probable_slot_time(const struct parq_ul_queue *q)
{
	uint e;
	double factor;

	if (statx_n(q->slot_stats) < STAT_MIN_POINTS)
		return 0;

	STATIC_ASSERT(STAT_MIN_POINTS >= 2);	/* Need 2 to compute variance */

	/*
	 * 95% of the data will fall below the average + 2 standard deviation,
	 * assuming normal distribution of the data points.
	 *
	 * If we're more optimistic, we can take the simple average plus the
	 * half of the standard deviation.
	 */

	factor = GNET_PROPERTY(parq_optimistic) ? 0.5 : 2.0;
	e = (uint) (statx_avg(q->slot_stats) + factor * statx_sdev(q->slot_stats));

	return e;
}

/**
 * Compute estimate for the time it will take to upload the whole file (or
 * a fraction of it if we are optimistic) at a given queue position.
 */
static uint
parq_estimated_slot_time(const struct parq_ul_queued *puq)
{
	filesize_t remaining;
	uint avg_bps;
	uint d;
	uint pd;

	avg_bps = bsched_avg_bps(BSCHED_BWS_OUT);
	avg_bps = MAX(1, avg_bps);

	/* XXX unsigned int has only 32 bit.
	 * XXX this is no proper  way to calculate in C using integer arithmetic.
	 */

	remaining = puq->file_size - puq->downloaded;
	d = remaining / avg_bps * GNET_PROPERTY(max_uploads);
	if (GNET_PROPERTY(parq_optimistic)) {
		uint n;

		n = puq->sha1 ? dmesh_count(puq->sha1) : 0;
		if (n > 1) {
			d /= n;
		}
	}
	pd = parq_probable_slot_time(puq->queue);	/* 0 if cannot compute */

	return pd ? MIN(pd, d) : d;
}

/**
 * Updates the ETA of all queued items in the given queue.
 */
static void
parq_upload_update_eta(struct parq_ul_queue *which_ul_queue)
{
	plist_t *l;
	uint eta = 0;
	uint avg_bps;
	time_delta_t running_time = delta_time(tm_time(), parq_start);
	hash_list_iter_t *iter;

	avg_bps = bsched_avg_bps(BSCHED_BWS_OUT);
	avg_bps = MAX(1024, avg_bps);		/* Assume at least 1 KiB/s */
	if (GNET_PROPERTY(parq_optimistic))
		avg_bps = MAX(avg_bps, GNET_PROPERTY(bw_http_out));

	if (which_ul_queue->active_uploads) {
		/*
		 * Current queue has an upload slot. Use this one for a start ETA.
		 * Locate the first active upload in this queue.
		 */

		PLIST_FOREACH(which_ul_queue->by_position, l) {
			struct parq_ul_queued *puq = l->data;

			if (puq->has_slot) {		/* Recompute ETA */
				eta += parq_estimated_slot_time(puq);
				break;
			}
		}
	}

	if (eta == 0 && GNET_PROPERTY(ul_running) > GNET_PROPERTY(max_uploads)) {
		/* We don't have an upload slot available, so a start ETA (for position
		 * 1) is necessary.
		 * Use the eta of another queue. First by the queue which uses more than
		 * one upload slot. If that result is still 0, we have a small problem
		 * as the ETA can't be calculated correctly anymore.
		 */

		eta = parq_probable_slot_time(which_ul_queue);

		for (l = ul_parqs; l && 0 == eta; l = plist_next(l)) {
			struct parq_ul_queue *q = l->data;

			eta = parq_probable_slot_time(q);
		}

		if (eta == 0 && GNET_PROPERTY(parq_debug))
			g_warning("[PARQ UL] Was unable to calculate an accurate ETA");
	}

	iter = hash_list_iterator(which_ul_queue->by_rel_pos);

	while (hash_list_iter_has_next(iter)) {
		struct parq_ul_queued *puq = hash_list_iter_next(iter);

		g_assert(puq->is_alive);

		puq->eta = eta;

		if (puq->has_slot)
			continue;			/* Skip already uploading uploads */

		/*
		 * Recalculate ETA of queued slots
		 *
		 * For the first "max_uploads" ones, we use the normal computation.
		 * For slots further away, we further compute the average time it
		 * would take to move to a runnable slot based on global removal
		 * rate from all the queues.
		 */

		if (puq->relative_position > GNET_PROPERTY(max_uploads)) {
			time_delta_t per_slot = running_time / MAX(1, parq_slots_removed);
			uint cheap_eta = puq->relative_position * per_slot;

			if (cheap_eta < eta)
				puq->eta = cheap_eta;
		}

		eta += parq_estimated_slot_time(puq);
	}

	hash_list_iter_release(&iter);
}

/**
 * Decreases the position of all queued items after the given queued item.
 */
static void
parq_upload_decrease_all_after(struct parq_ul_queued *puq)
{
	plist_t *l;
	int pos_cnt = 0;	/* Used for assertion */

	g_assert(puq != NULL);
	g_assert(puq->queue != NULL);
	g_assert(puq->queue->by_position != NULL);
	g_assert(puq->queue->by_position_length > 0);

	l = plist_find(puq->queue->by_position, puq);
	pos_cnt = ((struct parq_ul_queued *) l->data)->position;

	l = plist_next(l);	/* Decrease _after_ current parq */

	/*
	 * Cycle through list and decrease all positions by one. Position should
	 * never reach 0 which would mean the queued item is currently uploading
	 */
	for (;	l; l = plist_next(l)) {
		struct parq_ul_queued *p = l->data;

		g_assert(p != NULL);
		g_assert(p->position > 1);
		g_assert(p->position - 1 == UNSIGNED(pos_cnt));

		p->position--;
		pos_cnt++;
	}
}

/**
 * Function used to keep the relative position list sorted by absolute
 * queue positions, which refer to the order of arrival in the queue.
 */
static int
parq_ul_rel_pos_cmp(const void *a, const void *b)
{
	const struct parq_ul_queued *as = a, *bs = b;

	return CMP(as->position, bs->position);
}

/**
 * Insert item in relative position list.
 */
static inline void
parq_upload_insert_relative(struct parq_ul_queued *puq)
{
	parq_ul_queued_check(puq);

	g_assert(!(puq->flags & PARQ_UL_FROZEN));

	puq->relative_position = 0;
	hash_list_insert_sorted(puq->queue->by_rel_pos, puq, parq_ul_rel_pos_cmp);
}

/**
 * Remove item from relative position list.
 */
static inline void
parq_upload_remove_relative(struct parq_ul_queued *puq)
{
	parq_ul_queued_check(puq);

	hash_list_remove(puq->queue->by_rel_pos, puq);
	parq_slots_removed++;
}

/**
 * Recomputes all absolute positions of given queue.
 *
 * @param q		the queue for which we wish to recompute position
 */
static void
parq_upload_recompute_positions(struct parq_ul_queue *q)
{
	uint pos = 0;
	uint prev_pos = 0;
	plist_t *l;

	parq_ul_queue_check(q);

	PLIST_FOREACH(q->by_position, l) {
		struct parq_ul_queued *puq = l->data;

		parq_ul_queued_check(puq);
		g_assert(puq->queue == q);
		g_assert_log(puq->position > prev_pos,	/* Was sorted by construction */
			"pos=%u,, prev=%u", puq->position, prev_pos);

		prev_pos = puq->position;
		puq->position = ++pos;
	}

	g_assert(pos <= UNSIGNED(q->by_position_length));
}

/**
 * Recomputes all relative positions of given queue.
 *
 * @param q		the queue for which we wish to recompute position
 */
static void
parq_upload_recompute_relative_positions(struct parq_ul_queue *q)
{
	uint rel = 0;
	uint prev_rel = 0;
	uint prev_pos = 0;
	hash_list_iter_t *iter;

	parq_ul_queue_check(q);

	iter = hash_list_iterator(q->by_rel_pos);

	while (hash_list_iter_has_next(iter)) {
		struct parq_ul_queued *puq = hash_list_iter_next(iter);

		parq_ul_queued_check(puq);
		g_assert(puq->queue == q);
		g_assert_log(
			0 == puq->relative_position || puq->relative_position > prev_rel,
			"rel=%u, prev=%u", puq->relative_position, prev_rel);
		g_assert_log(puq->position > prev_pos,			/* Was sorted */
			"pos=%u, prev=%u", puq->position, prev_pos);

		if (puq->relative_position != 0)
			prev_rel = puq->relative_position;
		prev_pos = puq->position;
		puq->relative_position = ++rel;
	}

	hash_list_iter_release(&iter);

	g_assert(rel <= UNSIGNED(q->by_position_length));
	g_assert(hash_list_length(q->by_rel_pos) == rel);
}

/**
 * Set frozen flag on upload entry.
 */
static void
parq_upload_frozen_set(struct parq_ul_queued *puq)
{
	parq_ul_queued_check(puq);
	g_assert(!(puq->flags & PARQ_UL_FROZEN));

	puq->flags |= PARQ_UL_FROZEN;

	puq->by_addr->frozen++;
	puq->queue->frozen++;
}

/**
 * Clear frozen flag on upload entry.
 */
static void
parq_upload_frozen_clear(struct parq_ul_queued *puq)
{
	parq_ul_queued_check(puq);
	g_assert(puq->flags & PARQ_UL_FROZEN);

	puq->flags &= ~PARQ_UL_FROZEN;

	g_assert(puq->by_addr->frozen > 0);
	g_assert(puq->queue->frozen > 0);

	puq->by_addr->frozen--;
	puq->queue->frozen--;
}

/**
 * removes an puq from the parq list and frees all its memory.
 */
static void
parq_upload_free(struct parq_ul_queued *puq)
{
	g_assert(puq != NULL);
	g_assert(puq->addr_and_name != NULL);
	g_assert(puq->queue != NULL);
	g_assert(puq->queue->by_position_length > 0);
	g_assert(puq->queue->by_position != NULL);
	g_assert(puq->by_addr != NULL);
	g_assert(puq->by_addr->total > 0);
	g_assert(puq->by_addr->uploading <= puq->by_addr->total);

	if (puq->u != NULL)
		puq->u->parq_ul = NULL;

	parq_upload_decrease_all_after(puq);

	if (puq->flags & PARQ_UL_QUEUE)
		hash_list_remove(ul_parq_queue, puq);

	puq->by_addr->list = plist_remove(puq->by_addr->list, puq);
	puq->by_addr->total--;

	if (puq->flags & PARQ_UL_FROZEN)
		parq_upload_frozen_clear(puq);

	if (puq->by_addr->total == 0) {
		g_assert(host_addr_equiv(puq->remote_addr, puq->by_addr->addr));
		g_assert(NULL == puq->by_addr->list);

		/* No more uploads from this ip, cleaning up */
		hevset_remove(ul_all_parq_by_addr, &puq->by_addr->addr);
		WFREE(puq->by_addr);

		g_assert(!hevset_contains(ul_all_parq_by_addr, &puq->remote_addr));
	}

	puq->by_addr = NULL;

	if (puq->is_alive) {
		g_assert(puq->queue->alive > 0);
		puq->queue->alive--;
		puq->is_alive = FALSE;
	} else {
		hash_list_remove(puq->queue->by_date_dead, puq);
	}

	/* Remove the current queued item from all lists */
	puq->queue->by_position = plist_remove(puq->queue->by_position, puq);

	parq_upload_remove_relative(puq);

	hikset_remove(ul_all_parq_by_addr_and_name, puq->addr_and_name);
	htable_remove(ul_all_parq_by_id, &puq->id);

	g_assert(!hash_list_contains(puq->queue->by_date_dead, puq));
	g_assert(!hash_list_contains(puq->queue->by_rel_pos, puq));

	/*
	 * Queued upload is now removed from all lists. So queue size can be
	 * safely decreased and new ETAs can be calculated.
	 */
	g_assert(puq->queue->by_position_length > 0);
	puq->queue->by_position_length--;

	/*
	 * Don't update ETA on shutdown, we don't need this information, so speed
	 * up the shutdown process. Also it is better not doing so as on shutdown
	 * not all entries are removed the 'correct' way, we just want to free
	 * the memory
	 */
	if (!parq_shutdown) {
		parq_upload_recompute_positions(puq->queue);
		parq_upload_recompute_relative_positions(puq->queue);
		parq_upload_update_eta(puq->queue);
	}

	/* Free the memory used by the current queued item */
	HFREE_NULL(puq->addr_and_name);
	atom_sha1_free_null(&puq->sha1);
	puq->name = NULL;

	if (GNET_PROPERTY(parq_debug) > 3)
		g_debug("PARQ UL: entry %s freed from memory", guid_hex_str(&puq->id));

	puq->magic = 0;
	WFREE(puq);
}

/**
 * Calculates the retry delay for an upload.
 *
 * @return the recommended retry delay.
 */
static uint32
parq_ul_calc_retry(struct parq_ul_queued *puq)
{
	int result = PARQ_TIMER_BY_POS +
		(puq->relative_position - 1) * (PARQ_TIMER_BY_POS / 2);

	if (GNET_PROPERTY(parq_optimistic)) {
		struct parq_ul_queued *puq_prev = NULL;
		uint avg_bps;

		avg_bps = bsched_avg_bps(BSCHED_BWS_OUT);
		avg_bps = MAX(1, avg_bps);

		puq_prev = hash_list_previous(puq->queue->by_rel_pos, puq);

		if (puq_prev != NULL && puq_prev->has_slot) {
			int fast_result =
				(puq_prev->chunk_size / avg_bps) * GNET_PROPERTY(max_uploads);

			result = MIN(result, fast_result);
		}
	}

	result = MIN(PARQ_MAX_UL_RETRY_DELAY, result);

	if (puq->flags & PARQ_UL_FROZEN)
		result = MAX(result, PARQ_RETRY_FROZEN);

	return result;
}

/**
 * Creates a new parq_ul_queue structure and places it in the ul_parqs
 * linked list.
 */
static struct parq_ul_queue *
parq_upload_new_queue(void)
{
	struct parq_ul_queue *queue;

	WALLOC0(queue);
	queue->magic = PARQ_UL_QUEUE_MAGIC;
	queue->active = TRUE;
	queue->slot_stats = statx_make();
	queue->by_rel_pos = hash_list_new(NULL, NULL);
	queue->by_date_dead = hash_list_new(NULL, NULL);

	ul_parqs = plist_append(ul_parqs, queue);
	ul_parqs_cnt++;
	queue->num = plist_length(ul_parqs);

	if (GNET_PROPERTY(parq_debug))
		g_debug("PARQ UL: Created new queue %d", queue->num);

	g_assert(ul_parqs != NULL);
	g_assert(ul_parqs->data != NULL);
	g_assert(queue != NULL);

	return queue;
}

/**
 * Looks up in which queue the current upload should be placed and if the queue
 * doesn't exist yet it will be created.
 *
 * @return a pointer to the queue in which the upload should be queued.
 */
static struct parq_ul_queue *
parq_upload_which_queue(struct upload *u)
{
	struct parq_ul_queue *queue;
	uint size = PARQ_UL_LARGE_SIZE;
	uint slot;

	/*
	 * Determine in which queue the upload should be placed. Upload queues:
	 * 600 Mi < size < oo
	 * 300 Mi < size <= 600 Mi
	 * 150 Mi < size <= 300 Mi
	 *  75 Mi < size <= 150 Mi
	 *   0 Mi < size <= 75 Mi
	 * Smallest: PARQ_UL_LARGE_SIZE / 2^(parq_upload_slots-1)
	 *
	 * If the size doesn't fit in any of the first n-1 queues, it is put
	 * into the last queue implicitly.
	 */

	for (slot = 1 ; slot < GNET_PROPERTY(max_uploads); slot++) {
		if (u->file_size > size)
			break;
		size = size / 2;
	}

	/* if necessary, create missing queues */
	while (plist_length(ul_parqs) < GNET_PROPERTY(max_uploads))
		parq_upload_new_queue();

	queue = plist_nth_data(ul_parqs, slot - 1);
	parq_ul_queue_check(queue);

	/* We might need to reactivate the queue */
	queue->active = TRUE;

	g_assert(queue->active);

	return queue;
}

/**
 * Updates the IP and name entry in the queued structure and makes sure the hash
 * table remains in sync
 */
static void
parq_upload_update_addr_and_name(struct parq_ul_queued *puq,
	struct upload *u)
{
	g_assert(puq != NULL);
	upload_check(u);
	g_assert(u->name != NULL);

	if (puq->addr_and_name != NULL) {
		hikset_remove(ul_all_parq_by_addr_and_name, puq->addr_and_name);
		HFREE_NULL(puq->addr_and_name);
		puq->name = NULL;
	}

	puq->addr_and_name = str_cmsg("%s %s",
		host_addr_to_string(u->addr), u->name);
	puq->name = strchr(puq->addr_and_name, ' ') + 1;

	hikset_insert_key(ul_all_parq_by_addr_and_name, &puq->addr_and_name);
}

/**
 * Creates a new upload structure and prefills some values. Returns a pointer to
 * the newly created ul_queued structure.
 */
static struct parq_ul_queued *
parq_upload_create(struct upload *u)
{
	time_t now = tm_time();
	struct parq_ul_queued *puq = NULL;
	struct parq_ul_queued *prev_puq = NULL;
	struct parq_ul_queue *q = NULL;
	uint eta = 0;
	uint rel_pos = 1;

	upload_check(u);
	g_assert(ul_all_parq_by_addr_and_name != NULL);
	g_assert(ul_all_parq_by_id != NULL);

	q = parq_upload_which_queue(u);
	g_assert(q != NULL);

	/* Locate the last alive queued item so we can calculate the ETA */
	prev_puq = hash_list_tail(q->by_rel_pos);

	if (prev_puq != NULL) {
		parq_ul_queued_check(prev_puq);
		g_assert(prev_puq->is_alive);	/* Must be to belong to that list */

		rel_pos = prev_puq->relative_position + 1;

		eta = prev_puq->eta;

		if (GNET_PROPERTY(max_uploads) <= 0) {
			eta = (uint) -1;
		} else {
			eta += parq_estimated_slot_time(prev_puq);
		}
	}

	/* Will append item to the list */
	g_assert(hash_list_length(q->by_rel_pos) + 1 == rel_pos);

	/* Create new parq_upload item */
	WALLOC0(puq);
	puq->magic = PARQ_UL_MAGIC;

	/* Create identifier to find upload again later. IP + Filename */
	puq->remote_addr = u->addr;
	parq_upload_update_addr_and_name(puq, u);
	puq->sha1 = u->sha1 ? atom_sha1_get(u->sha1) : NULL;

	/* Create a random ID */
	guid_random_fill(&puq->id);

	g_assert(puq->addr_and_name != NULL);

	/* Fill puq structure */
	puq->position = q->by_position_length + 1;
	puq->relative_position = rel_pos;
	puq->eta = eta;
	puq->enter = now;
	puq->updated = now;
	puq->file_size = u->file_size;
	puq->downloaded = u->downloaded;
	puq->queue = q;
	puq->has_slot = FALSE;
	puq->addr = zero_host_addr;
	puq->port = 0;
	puq->major = 0;
	puq->minor = 0;
	puq->active_queued = FALSE;
	puq->is_alive = TRUE;
	puq->had_slot =  FALSE;
	puq->quick = FALSE;
	puq->queue->alive++;
	/*
	 * On create, set the retry to now. If we use the
	 * now + parq_ul_calc_retry method, the new request
	 * would immediatly be followed by a "requested too soon"
	 * error.
	 */
	puq->retry = now;
	puq->expire = time_advance(puq->retry, MIN_LIFE_TIME);
	puq->ban_timeout = 0;
	puq->disc_timeout = 0;
	puq->uploaded_size = 0;
	puq->slot_granted = 0;

	/* Save into hash table so we can find the current parq ul later */
	htable_insert(ul_all_parq_by_id, &puq->id, puq);

	q->by_position_length++;
	q->by_position = plist_append(q->by_position, puq);

	hash_list_append(puq->queue->by_rel_pos, puq);

	if (GNET_PROPERTY(parq_debug) > 3) {
		g_debug("PARQ UL Q %d/%zd (%3d[%3d]/%3d): New: %s \"%s\"; ID=\"%s\"",
			puq->queue->num,
			plist_length(ul_parqs),
			puq->position,
			puq->relative_position,
			puq->queue->by_position_length,
			host_addr_to_string(puq->remote_addr),
			puq->name,
			guid_hex_str(&puq->id));
	}

	/* Check if the requesting client has already other PARQ entries */
	puq->by_addr = hevset_lookup(ul_all_parq_by_addr, &puq->remote_addr);

	if (puq->by_addr == NULL) {
		/* The requesting client has no other PARQ entries yet, create an ip
		 * reference structure */
		WALLOC0(puq->by_addr);
		puq->by_addr->addr = puq->remote_addr;
		hevset_insert_key(ul_all_parq_by_addr, &puq->by_addr->addr);
		puq->by_addr->uploading = 0;
		puq->by_addr->total = 0;
		puq->by_addr->list = NULL;
	}

	g_assert(host_addr_equiv(puq->by_addr->addr, puq->remote_addr));

	puq->by_addr->total++;
	puq->by_addr->list = plist_prepend(puq->by_addr->list, puq);

	g_assert(puq != NULL);
	g_assert(puq->position > 0);
	g_assert(puq->addr_and_name != NULL);
	g_assert(puq->name != NULL);
	g_assert(puq->queue != NULL);
	g_assert(puq->queue->by_position != NULL);
	g_assert(puq->queue->by_rel_pos != NULL);
	g_assert(puq->queue->by_position->data != NULL);
	g_assert(puq->relative_position > 0);
	g_assert(puq->relative_position <=
		UNSIGNED(puq->queue->by_position_length));
	g_assert(puq->by_addr != NULL);
	g_assert(puq->by_addr->uploading <= puq->by_addr->total);

	return puq;
}

/**
 * Renumber queues after a queue has been removed from the list.
 */
static void
parq_upload_recompute_queue_num(void)
{
	plist_t *l;
	int pos = 0;

	PLIST_FOREACH(ul_parqs, l) {
		struct parq_ul_queue *q = l->data;

		q->num = ++pos;
	}
}

/**
 * Frees the queue from memory and the ul_parqs linked list.
 */
static void
parq_upload_free_queue(struct parq_ul_queue *queue)
{
	parq_ul_queue_check(queue);
	g_assert(ul_parqs != NULL);

	/* Never ever remove a queue which is in use and/or marked as active */
	g_assert(queue->by_position_length == 0);
	g_assert(queue->active_uploads == 0);
	g_assert(!queue->active);

	if (GNET_PROPERTY(parq_debug))
		g_debug("PARQ UL: removing inactive queue %d", queue->num);

	/* Remove queue from the list containing all the queues */
	ul_parqs = plist_remove(ul_parqs, queue);
	parq_upload_recompute_queue_num();

	g_assert(ul_parqs_cnt > 0);
	ul_parqs_cnt--;

	/* Free memory */
	hash_list_free(&queue->by_rel_pos);
	hash_list_free(&queue->by_date_dead);
	statx_free(queue->slot_stats);
	queue->magic = 0;
	WFREE(queue);
}

/**
 * Find the parq upload entry based on the PARQ ID found in the X-Queued header.
 */
static struct parq_ul_queued *
parq_upload_find_id(const struct upload *u, const header_t *header)
{
	char *buf;

	buf = header_get(header, "X-Queued");
	if (buf != NULL) {
		const char *id_str = get_header_value(buf, "ID", NULL);

		if (id_str) {
			struct guid id;

			if (hex_to_guid(id_str, &id)) {
				struct parq_ul_queued *puq;
				puq = htable_lookup(ul_all_parq_by_id, &id);
				/* In case we missed it earlier, record PARQ support */
				if (puq != NULL)
					puq->supports_parq = TRUE;
				return puq;
			}
			return NULL;
		}
		if (debugging(0)) {
			g_warning("[PARQ UL] missing ID in PARQ request from %s",
				upload_host_info(u));
			if (GNET_PROPERTY(parq_debug) > 1) {
				g_warning("[PARQ UL] header dump:");
				header_dump(stderr, header, NULL);
			}
		}
	}
	return NULL;
}

/**
 * Determine if we are still sharing this file, so that PARQ can
 * determine if it makes sense to keep this file in the queue.
 *
 * @return FALSE if the file is no longer shared, or TRUE if the file
 * is shared or if we don't know, e.g. if the library is being
 * rebuilt.
 */
static bool
parq_still_sharing(struct parq_ul_queued *puq)
{
	shared_file_t *sf;

	if (puq->flags & PARQ_UL_SPECIAL)
		return TRUE;

	if (puq->sha1) {
		sf = shared_file_by_sha1(puq->sha1);
		if (NULL == sf) {
			if (GNET_PROPERTY(parq_debug))
				g_debug("[PARQ UL] We no longer share this file: "
					"SHA1=%s \"%s\"",
					sha1_base32(puq->sha1), puq->name);
			return FALSE;
		}
		shared_file_unref(&sf);
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
		sf = shared_file_by_name(puq->name);
		if (sf != SHARE_REBUILDING) {
			if (NULL != sf && sha1_hash_available(sf)) {
				puq->sha1 = atom_sha1_get(shared_file_sha1(sf));
				g_message("[PARQ UL] found SHA1=%s for \"%s\"",
					sha1_base32(puq->sha1), puq->name);
				shared_file_unref(&sf);
				return TRUE;
			} else {
				if (GNET_PROPERTY(parq_debug))
					g_debug("[PARQ UL] We no longer share this file \"%s\"",
						puq->name);
				shared_file_unref(&sf);
				return FALSE;
			}
		}
	}

	/* Return TRUE by default because this is the safest condition */
	return TRUE;
}

/**
 * Possibly register the upload in the list for deferred QUEUE sending.
 */
static void
parq_upload_register_send_queue(struct parq_ul_queued *puq)
{
	g_assert(!(puq->flags & PARQ_UL_QUEUE));

	/* Not a PARQ-aware host */
	if (!puq->supports_parq) {
		if (GNET_PROPERTY(parq_debug) > 2) {
			g_debug("PARQ UL Q %d/%d (%3d[%3d]/%3d): "
				"not PARQ-aware, not sending QUEUE: %s '%s'",
				  puq->queue->num,
				  ul_parqs_cnt,
				  puq->position,
				  puq->relative_position,
				  puq->queue->by_position_length,
				  host_addr_to_string(puq->remote_addr),
				  puq->name
			);
		}
		puq->flags |= PARQ_UL_NOQUEUE;
		return;
	}

	/* No known connect back port / ip */
	if (!host_is_valid(puq->addr, puq->port)) {
		if (GNET_PROPERTY(parq_debug) > 2) {
			g_debug("PARQ UL Q %d/%d (%3d[%3d]/%3d): "
				"no valid address to send QUEUE: %s '%s'",
				  puq->queue->num,
				  ul_parqs_cnt,
				  puq->position,
				  puq->relative_position,
				  puq->queue->by_position_length,
				  host_addr_to_string(puq->remote_addr),
				  puq->name
			);
		}
		puq->flags |= PARQ_UL_NOQUEUE;
		return;
	}

	hash_list_append(ul_parq_queue, puq);
	puq->flags |= PARQ_UL_QUEUE;
}

/**
 * Finds an upload if available in the upload queue.
 *
 * @return NULL if upload could not be found.
 */
static inline struct parq_ul_queued *
parq_upload_find(const struct upload *u)
{
	char buf[1024 + 128];

	upload_check(u);
	g_assert(ul_all_parq_by_addr_and_name != NULL);
	g_assert(ul_all_parq_by_id != NULL);

	if (u->parq_ul) {
		return u->parq_ul;
	} else if (u->name) {
		concat_strings(buf, sizeof buf,
			host_addr_to_string(u->addr), " ", u->name,
			NULL_PTR);
		return hikset_lookup(ul_all_parq_by_addr_and_name, buf);
	} else {
		return NULL;
	}
}

/**
 * Compute the time at which we should send the next QUEUE callback for
 * a given entry.
 */
static time_t parq_upload_next_queue(time_t last, struct parq_ul_queued *puq)
{
	return time_advance(last, QUEUE_PERIOD * (1 + (puq->queue_sent - 1) / 2.0));
}

/**
 * Sends a QUEUE to a parq enabled client.
 */
static void
parq_upload_send_queue(struct parq_ul_queued *puq)
{
	struct gnutella_socket *s;
	struct upload *u;
	time_t now = tm_time();
	uint32 flags = GNET_PROPERTY(tls_enforce) ? SOCK_F_TLS : 0;

	g_assert(puq->flags & PARQ_UL_QUEUE);

	puq->last_queue_sent = now;		/* We tried... */
	puq->queue_sent++;
	puq->send_next_queue = parq_upload_next_queue(now, puq);
	puq->by_addr->last_queue_sent = now;

	if (GNET_PROPERTY(parq_debug)) {
		g_debug("PARQ UL Q %d/%d (%3d[%3d]/%3d): "
			"Sending QUEUE #%d to %s for ID=%s: '%s'",
			puq->queue->num,
			ul_parqs_cnt,
			puq->position,
			puq->relative_position,
			puq->queue->by_position_length,
			puq->queue_sent,
			host_addr_port_to_string(puq->addr, puq->port),
			guid_hex_str(&puq->id),
			puq->name);
	}

	gnet_stats_inc_general(GNR_PARQ_QUEUE_SENDING_ATTEMPTS);

	s = socket_connect(puq->addr, puq->port, SOCK_TYPE_UPLOAD, flags);

	if (!s) {
		g_warning("[PARQ UL] could not send QUEUE #%d to %s ID=%s "
			"(can't connect)",
			puq->queue_sent,
			host_addr_port_to_string(puq->addr, puq->port),
			guid_hex_str(&puq->id));
		puq->flags &= ~PARQ_UL_QUEUE;
		return;
	}

	u = upload_create(s, TRUE);

	u->status = GTA_UL_QUEUE;
	u->name = atom_str_get(puq->name);

	parq_upload_update_addr_and_name(puq, u);
	upload_fire_upload_info_changed(u);

	/* Verify created upload entry */
	g_assert(parq_upload_find(u) == puq);

	u->parq_ul = puq;

	/* Prevent too frequent QUEUE sending to the same host */
	aging_insert(ul_queue_sent, WCOPY(&puq->by_addr->addr), uint_to_pointer(1));
}

/**
 * Invoked when we did not succeed in connecting to the remote server
 * to send the QUEUE callback.
 */
static void
parq_upload_send_queue_failed(struct parq_ul_queued *puq)
{
	g_assert(puq);

	puq->flags &= ~PARQ_UL_QUEUE;
	puq->by_addr->last_queue_failure = tm_time();

	if (GNET_PROPERTY(parq_debug) > 3) {
		g_debug("PARQ UL: QUEUE callback not sent, ID=%s: "
			"could not connect to %s",
			guid_hex_str(&puq->id),
			host_addr_to_string(puq->by_addr->addr));
	}
}

/**
 * Adds an ip to the parq ban list.
 *
 * This list is used to deny connections from such a host. Sources will
 * only make it in this list when they ignore our delay Retry-After header
 * twice.
 */
static void
parq_add_banned_source(const host_addr_t addr, time_t delay)
{
	time_t now = tm_time();
	struct parq_banned *banned = NULL;

	g_assert(ht_banned_source != NULL);

	banned = hevset_lookup(ht_banned_source, &addr);
	if (banned == NULL) {
		/* Host not yet banned yet, good */
		WALLOC0(banned);
		banned->addr = addr;

		hevset_insert_key(ht_banned_source, &banned->addr);
		parq_banned_sources = plist_append(parq_banned_sources, banned);
	}

	g_assert(banned != NULL);
	g_assert(host_addr_equiv(banned->addr, addr));

	/* Update timestamp */
	banned->added = now;
	if (banned->expire < time_advance(now, delay)) {
		banned->expire = time_advance(now, delay);
	}
}

/**
 * Removes a banned ip from the parq banned list.
 */
static void
parq_del_banned_source(const host_addr_t addr)
{
	struct parq_banned *banned = NULL;

	g_assert(ht_banned_source != NULL);
	g_assert(parq_banned_sources != NULL);

	banned = hevset_lookup(ht_banned_source, &addr);

	g_assert(banned != NULL);
	g_assert(host_addr_equiv(banned->addr, addr));

	hevset_remove(ht_banned_source, &addr);
	parq_banned_sources = plist_remove(parq_banned_sources, banned);

	WFREE(banned);
}

/**
 * Cleanup banned uploading IPs.
 */
static void
parq_cleanup_banned(time_t now)
{
	plist_t *dl;
	pslist_t *sl, *to_remove = NULL;

	PLIST_FOREACH(parq_banned_sources, dl) {
		struct parq_banned *banned = dl->data;

		if (
			delta_time(now, banned->added) > PARQ_MAX_UL_RETRY_DELAY ||
			delta_time(now, banned->expire) > 0
		) {
			to_remove = pslist_prepend(to_remove, banned);
		}
	}

	PSLIST_FOREACH(to_remove, sl) {
		struct parq_banned *banned = sl->data;

		parq_del_banned_source(banned->addr);
	}

	pslist_free(to_remove);
}

/**
 * Periodic timer called to scan the "dead" list and see whether we
 * should send a QUEUE callback.
 */
static void
parq_ul_queue_dead_timer(time_t now, const struct parq_ul_queue *q)
{
	hash_list_iter_t *iter;

	iter = hash_list_iterator(q->by_date_dead);

	while (hash_list_iter_has_next(iter)) {
		struct parq_ul_queued *puq = hash_list_iter_next(iter);

		g_assert(puq != NULL);

		/* Entry can't have a slot, and we know it expired! */

		if (
			!(puq->flags & (PARQ_UL_QUEUE|PARQ_UL_NOQUEUE)) &&
			delta_time(puq->send_next_queue, now) < 0 &&
			puq->queue_sent < MAX_QUEUE &&
			puq->queue_refused < MAX_QUEUE_REFUSED &&
			!ban_is_banned(BAN_CAT_SOCKET, puq->remote_addr)
		)
			parq_upload_register_send_queue(puq);
	}

	hash_list_iter_release(&iter);
}

/**
 * Callout queue periodic event to scan dead entries in queues.
 */
static bool
parq_dead_timer(void *unused_udata)
{
	time_t now = tm_time();
	plist_t *l;

	(void) unused_udata;

	if (0 == GNET_PROPERTY(max_uploads))	/* Sharing disabled */
		return TRUE;

	PLIST_FOREACH(ul_parqs, l) {
		struct parq_ul_queue *q = l->data;
		parq_ul_queue_dead_timer(now, q);	/* Send QUEUE if possible */
	}

	return TRUE;		/* Keep calling */
}

/**
 * Periodic scanning of the alive queued entries.
 *
 * @param now		current time
 * @param q			the queue to scan
 * @param rlp		holds pointer to the single list of items to remove
 */
static void
parq_upload_queue_timer(time_t now, struct parq_ul_queue *q, pslist_t **rlp)
{
	hash_list_iter_t *iter;
	pslist_t *to_remove = *rlp;

	iter = hash_list_iterator(q->by_rel_pos);

	while (hash_list_iter_has_next(iter)) {
		struct parq_ul_queued *puq = hash_list_iter_next(iter);
		time_delta_t grace;

		g_assert(puq != NULL);

		if (
			puq->expire <= now &&
			!puq->has_slot &&
			!(puq->flags & (PARQ_UL_QUEUE|PARQ_UL_NOQUEUE)) &&
			delta_time(puq->send_next_queue, now) < 0 &&
			puq->queue_sent < MAX_QUEUE &&
			puq->queue_refused < MAX_QUEUE_REFUSED &&
			GNET_PROPERTY(max_uploads) > 0 &&
			!ban_is_banned(BAN_CAT_SOCKET, puq->remote_addr)
		)
			parq_upload_register_send_queue(puq);

		/*
		 * Even if the upload is flagged with PARQ_UL_QUEUE to indicate that
		 * we are planning to send it a QUEUE callback at some point, it is
		 * possible that we may be waiting a very long time before being able
		 * to send the QUEUE message back, due to outgoing bandwidth shortage,
		 * or because there are many uploads from the same host and we throttle
		 * QUEUE sending to avoid hammering the remote host.
		 *
		 * To free up the slot they are using, we let them expire nonetheless,
		 * after PARQ_QUEUE_GRACE_TIME extra time.  They will be moved to the
		 * "dead" queue, where we will continue to schedule QUEUE callbacks.
		 * However, they can be dropped from the "dead" queue as soon as we
		 * run out of PARQ slots.
		 *
		 *		--RAM, 2013-08-30
		 */

		grace = PARQ_GRACE_TIME +
			((puq->flags & PARQ_UL_QUEUE) ? PARQ_QUEUE_GRACE_TIME : 0);

		if (
			puq->is_alive &&
			delta_time(now, puq->expire) > grace &&
			!puq->has_slot
		) {
			if (GNET_PROPERTY(parq_debug) > 3)
				g_debug("PARQ UL Q %d/%d (%3d[%3d]/%3d): "
					"Timeout: ID=%s %s '%s'",
					puq->queue->num,
					ul_parqs_cnt,
					puq->position,
					puq->relative_position,
					puq->queue->by_position_length,
					guid_hex_str(&puq->id),
					host_addr_to_string(puq->remote_addr),
					puq->name);


			/*
			 * Mark for removal. Can't remove now as we are still using the
			 * ul_parq_by_position linked list. (prepend is probably the
			 * fastest function)
			 */
			to_remove = pslist_prepend(to_remove, puq);
		}
	}

	hash_list_iter_release(&iter);

	*rlp = to_remove;
}

/*
 * Send out QUEUE callbacks for all the entries registered.
 */
static void
parq_upload_send_queue_callbacks(time_t now)
{
	void *next;

	if (
		GNET_PROPERTY(library_rebuilding) ||
		0 == hash_list_length(ul_parq_queue) ||
		0 == GNET_PROPERTY(max_uploads) ||
		GNET_PROPERTY(net_buffer_shortage)
	)
		return;

	/*
	 * Use an iteration method allowing the removal of items whilst we
	 * traverse the hash_list structure.  See hash_list_next() comment.
	 */

	next = hash_list_head(ul_parq_queue);
	while (next) {
		struct parq_ul_queued *puq = next;
		bool has_timedout;
		time_t last_queue_sent;
		time_t last_queue_failure;

		next = hash_list_next(ul_parq_queue, next);

		if (
			GNET_PROPERTY(ul_registered) > MAX_UPLOADS ||
			!bws_can_connect(SOCK_TYPE_UPLOAD)
		)
			break;

		last_queue_sent = puq->by_addr->last_queue_sent;	/* To that IP */
		last_queue_failure = puq->by_addr->last_queue_failure;

		has_timedout =
			delta_time(now, last_queue_sent) < QUEUE_PERIOD &&
			delta_time(now, last_queue_failure) < QUEUE_PERIOD;

		/*
		 * If a previous QUEUE command could not connect to this IP during
		 * this timeframe, we can safely ignore all QUEUE commands for this
		 * IP now.
		 */

		if (
			has_timedout &&
			delta_time(puq->send_next_queue, now) < 0
		) {

			if (GNET_PROPERTY(parq_debug) > 3) {
				g_debug("PARQ UL: removing QUEUE callback due to other "
					"failed QUEUE callbacks for IP: %s",
					host_addr_to_string(puq->by_addr->addr));
			}
			puq->last_queue_sent = last_queue_sent;	/* We considered it... */
			puq->flags &= ~PARQ_UL_QUEUE;
			goto remove;
		}

		/*
		 * Don't send QUEUE if the current IP has been sent one recently.
		 */

		if (aging_lookup(ul_queue_sent, &puq->by_addr->addr)) {
			if (GNET_PROPERTY(parq_debug) > 2) {
				g_debug("PARQ UL: not sending QUEUE since we sent one "
					"recently to IP: %s",
					host_addr_to_string(puq->by_addr->addr));
			}
			continue;		/* Do not remove from list. move forward */
		} else {
			parq_upload_send_queue(puq);

			/*
			 * Do not clear PARQ_UL_QUEUE yet since this entry cannot be
			 * considered for another QUEUE until we know the fate of the
			 * connect back attempt.
			 */
		}

		/* FALL THROUGH */

	remove:
		hash_list_remove(ul_parq_queue, puq);
	}
}

/**
 * Removes any PARQ uploads which show no activity.
 */
void
parq_upload_timer(time_t now)
{
	static uint startup_delay;
	plist_t *queues;
	pslist_t *sl, *to_remove = NULL;
	uint queue_selected = 0;

	if (!parq_is_enabled())
		return;

	/*
	 * Don't do anything with parq during the first 10 seconds. Looks like
	 * PROP_LIBRARY_REBUILDING is not set yet immediatly at the first time, so
	 * there may be some other things not set properly yet neither.
	 */
	if (startup_delay < 10) {
		startup_delay++;
		return;
	}

	parq_cleanup_banned(now);		/* PARQ ip banning timer */

	/*
	 * Scan the queues.
	 */

	PLIST_FOREACH(ul_parqs, queues) {
		struct parq_ul_queue *queue = queues->data;

		queue_selected++;

		parq_upload_queue_timer(now, queue, &to_remove);

		/*
		 * Mark queue as inactive when there are less uploads slots available.
		 */
		queue->active =
			booleanize(queue_selected <= GNET_PROPERTY(max_uploads));
	}

	/*
	 * Sort out dead entries.
	 */

	PSLIST_FOREACH(to_remove, sl) {
		struct parq_ul_queued *puq = sl->data;

		parq_ul_queued_check(puq);

		puq->is_alive = FALSE;
		g_assert(puq->queue->alive > 0);
		puq->queue->alive--;

		if (puq->flags & PARQ_UL_FROZEN)
			parq_upload_frozen_clear(puq);

		parq_upload_remove_relative(puq);
		puq->queue->recompute = TRUE;	/* Defer costly recomputations */

		if (enable_real_passive && parq_still_sharing(puq)) {
			hash_list_append(puq->queue->by_date_dead, puq);
		} else
			parq_upload_free(puq);
	}

	/*
	 * Recompute data only for the queues in which we removed items --RAM.
	 */

	PLIST_FOREACH(ul_parqs, queues) {
		struct parq_ul_queue *q = queues->data;

		if (q->recompute) {
			parq_upload_recompute_relative_positions(q);
			parq_upload_update_eta(q);
			q->recompute = FALSE;
		}
	}

	pslist_free_null(&to_remove);

	/*
	 * If the last queue is not active anymore (ie it should be removed
	 * as soon as the queue is empty) and there are no more queued items
	 * in the queue, remove the queue.
	 */
	queues = plist_last(ul_parqs);

	if (queues != NULL) {
		struct parq_ul_queue *queue = queues->data;
		if (!queue->active && queue->by_position_length == 0) {
			parq_upload_free_queue(queue);
		}
	}

	parq_upload_send_queue_callbacks(now);
}

/**
 * @return TRUE if parq cannot hold any more uploads.
 */
bool
parq_upload_queue_full(struct upload *u)
{
	struct parq_ul_queue *q;
	struct parq_ul_queued *puq;

	upload_check(u);

	q = parq_upload_which_queue(u);
	g_assert(q->by_position_length >= q->alive);

	if (UNSIGNED(q->by_position_length) < parq_max_upload_size)
		return FALSE;

	if (0 == hash_list_length(q->by_date_dead))
		return TRUE;		/* No dead entries to remove */

	puq = hash_list_head(q->by_date_dead);

	parq_ul_queued_check(puq);

	if (GNET_PROPERTY(parq_debug) > 1)
		g_debug("PARQ UL: removing dead upload %s \"%s\" from %s",
				guid_hex_str(&puq->id), puq->name,
				host_addr_to_string(puq->remote_addr));

	parq_upload_free(puq);
	return FALSE;
}

/**
 * Whether the current upload is already queued.
 */
bool
parq_upload_queued(struct upload *u)
{
	return parq_upload_lookup_position(u) != (uint) -1;
}

/**
 * @return TRUE if the current upload will finish quickly enough and
 * actually scheduling would only cost more resources then it would
 * save.
 */
static bool
parq_upload_quick_continue(struct parq_ul_queued *puq)
{
	uint avg_bps;
	filesize_t total;

	g_assert(puq);

	/*
	 * Compute total amount of data that has been requested by the remote
	 * host so far, adding the current request size to the already downloaded
	 * amount.
	 */

	total = puq->uploaded_size + puq->chunk_size;

	if (total < GNET_PROPERTY(parq_size_always_continue))
		return TRUE;

	if (GNET_PROPERTY(parq_time_always_continue) > 0) {
		avg_bps = bsched_avg_bps(BSCHED_BWS_OUT);
		avg_bps = MAX(1, avg_bps);

		/*
		 * Determine the time this upload would need. Add + 1 to the
		 * number of used_slots to also include this upload in the
		 * calculation.
		 */
		if (
			(total * (GNET_PROPERTY(ul_running) + 1)) / avg_bps
				<= GNET_PROPERTY(parq_time_always_continue)
		)
			return TRUE;
	}

	return FALSE;
}

/**
 * Computes the amount of free upload slots available for queue.
 */
static int
free_upload_slots(struct parq_ul_queue *q)
{
	int slots_free;
	int even_slots;
	int remainder;
	int surplus;
	int available;
	int result;
	plist_t *l;

	/*
	 * Since by definition "quick" uploads do not last for long, they do
	 * not count as consuming an upload slot.  --RAM, 2007-08-16
	 */

	slots_free = GNET_PROPERTY(max_uploads) - GNET_PROPERTY(ul_running)
		+ GNET_PROPERTY(ul_quick_running);

	if (slots_free > 0 && UNSIGNED(slots_free) > GNET_PROPERTY(max_uploads))
		slots_free = GNET_PROPERTY(max_uploads);

	/*
	 * Determine the amount of slots that can be devoted to this queue.
	 *
	 * All the upload slots are evenly shared among the queues, but if
	 * a queue would need less than that amount, the surplus would be given
	 * to the target queue.
	 */

	g_assert(ul_parqs_cnt > 0);

	even_slots = GNET_PROPERTY(max_uploads) / ul_parqs_cnt;
	remainder = GNET_PROPERTY(max_uploads) - even_slots * ul_parqs_cnt;

	g_assert(remainder >= 0 && remainder < ul_parqs_cnt);

	/*
	 * Look at the surplus that can be donated.
	 *
	 * XXX we don't handle inactive queues (due to upload slot reduction).
	 * XXX we must decide how we handle their entries.
	 */

	surplus = 0;

	PLIST_FOREACH(ul_parqs, l) {
		struct parq_ul_queue *queue = l->data;
		int wanted = queue->alive - queue->active_uploads;

		g_assert(wanted >= 0);

		/*
		 * Frozen upload queue entries are not accounted as "wanted" because
		 * although they are active, they are not schedulable.
		 *
		 * Naturally, this means another upload from the same queue can be
		 * scheduled before the frozen one, even though the latter was ahead
		 * of the former in the queue.  That's what "frozen" is about.
		 *		--RAM, 2011-11-11
		 */

		if (queue->frozen >= wanted)
			wanted = 0;
		else
			wanted -= queue->frozen;

		if (wanted < even_slots)
			surplus += even_slots - wanted;

		if (GNET_PROPERTY(parq_debug) > 5) {
			g_debug("[PARQ UL] Q#%-2d "
				"alive=%-4d active=%-4d frozen=%-4d surplus=%-4d",
				queue->num,
				queue->alive, queue->active_uploads, queue->frozen,
				wanted < even_slots ? even_slots - wanted : 0);
		}
	}

	g_assert(surplus >= 0);

	if (slots_free < 0)
		slots_free = 0;		/* Must stay >= 0 for unsigned comparisons */

	/*
	 * The max amount of slots usable is: even_slots + remainder + surplus.
	 * To get overall available slots we can grant this queue, we need
	 * to remove the active uploads.
	 */

	available = even_slots + remainder + surplus - q->active_uploads;
	result = MIN(available, slots_free);
	result = MAX(0, result);

	if (GNET_PROPERTY(parq_debug) >= 5) {
		g_debug("[PARQ UL] %s(#%d): "
			"free_slots=%d (with %u quick), even=%d, remainder=%d, "
			"surplus=%d, usage=%d, usable=%d, avail=%d -> result=%d",
			G_STRFUNC, q->num, slots_free,
			GNET_PROPERTY(ul_quick_running), even_slots, remainder,
			surplus, q->active_uploads, even_slots + remainder + surplus,
			available, result);
	}

	return result;
}

/**
 * Mark all the entries which do not have a slot for this IP as "frozen",
 * thereby removing them from the PARQ scheduling logic until the amount
 * of slots used by this IP decreases.
 */
static void
parq_upload_freeze_all(struct parq_ul_queued *puq)
{
	plist_t *l;
	int frozen = 0;
	int extra = 0;

	g_assert(puq);
	g_assert(puq->by_addr);

	if (GNET_PROPERTY(parq_debug))
		g_debug("[PARQ UL] freezing entries for IP %s (has %d already)",
			host_addr_to_string(puq->by_addr->addr), puq->by_addr->frozen);

	PLIST_FOREACH(puq->by_addr->list, l) {
		struct parq_ul_queued *uqx = l->data;

		if (uqx->has_slot) {
			g_assert(!(uqx->flags & PARQ_UL_FROZEN));
			continue;
		}

		if (!(uqx->flags & PARQ_UL_FROZEN)) {
			if (GNET_PROPERTY(parq_debug) >= 5)
				g_debug("[PARQ UL] freezing %s %s [#%d] from IP %s (rel=%u)",
					uqx->is_alive ? "alive" : "dead",
					guid_hex_str(&uqx->id), uqx->queue->num,
					host_addr_to_string(puq->by_addr->addr),
					uqx->relative_position);

			parq_upload_remove_relative(uqx);
			parq_upload_frozen_set(uqx);
			uqx->queue->recompute = TRUE;	/* Defer update */
			extra++;
		}

		frozen++;
	}

	if (GNET_PROPERTY(parq_debug))
		g_debug("[PARQ UL] froze %d entr%s for IP %s (%d total)",
			extra, plural_y(extra),
			host_addr_to_string(puq->by_addr->addr), frozen);

	g_assert(puq->by_addr->frozen == frozen);

	/*
	 * Recompute data only for the queues in which we removed items.
	 */

	PLIST_FOREACH(ul_parqs, l) {
		struct parq_ul_queue *q = l->data;

		if (q->recompute) {
			parq_upload_recompute_relative_positions(q);
			q->recompute = FALSE;
		}
	}
}

/**
 * Unfreeze one entry, if needed.
 */
static void
parq_upload_unfreeze_one(struct parq_ul_queued *puq)
{
	g_assert(puq);
	g_assert(puq->by_addr);

	if (!(puq->flags & PARQ_UL_FROZEN))
		return;

	g_assert(!puq->has_slot);
	g_assert(puq->is_alive);

	if (GNET_PROPERTY(parq_debug) >= 5)
		g_debug("[PARQ UL] thawing one %s [#%d] from IP %s",
			guid_hex_str(&puq->id), puq->queue->num,
			host_addr_to_string(puq->by_addr->addr));

	parq_upload_frozen_clear(puq);

	g_assert(!hash_list_contains(puq->queue->by_rel_pos, puq));

	parq_upload_insert_relative(puq);
	parq_upload_recompute_relative_positions(puq->queue);
}

/**
 * Unfreeze all entries for given IP, allowing them to compete for a slot again.
 */
static void
parq_upload_unfreeze_all(struct parq_ul_queued *puq)
{
	plist_t *l;
	unsigned thawed = 0;
	unsigned inserted = 0;

	parq_ul_queued_check(puq);
	g_assert(puq->by_addr);

	if (GNET_PROPERTY(parq_debug))
		g_debug("[PARQ UL] thawing entries for IP %s (has %d)",
			host_addr_to_string(puq->by_addr->addr), puq->by_addr->frozen);

	PLIST_FOREACH(puq->by_addr->list, l) {
		struct parq_ul_queued *uqx = l->data;

		parq_ul_queued_check(uqx);

		if (uqx->flags & PARQ_UL_FROZEN) {
			g_assert(!uqx->has_slot);

			parq_upload_frozen_clear(uqx);
			if (uqx->is_alive) {
				parq_upload_insert_relative(uqx);
				uqx->queue->recompute = TRUE;		/* Defer update */
				inserted++;
			}

			if (GNET_PROPERTY(parq_debug) >= 5)
				g_debug("[PARQ UL] thawed %s %s [#%d] from IP %s",
					uqx->is_alive ? "alive" : "dead",
					guid_hex_str(&uqx->id), uqx->queue->num,
					host_addr_to_string(puq->by_addr->addr));

			thawed++;
		}
	}

	if (GNET_PROPERTY(parq_debug))
		g_debug("[PARQ UL] thawed %u entr%s for IP %s (%u of which alive)",
			thawed, plural_y(thawed),
			host_addr_to_string(puq->by_addr->addr), inserted);

	g_assert(0 == puq->by_addr->frozen);

	/*
	 * Recompute data only for the queues in which we inserted items.
	 */

	PLIST_FOREACH(ul_parqs, l) {
		struct parq_ul_queue *q = l->data;

		if (q->recompute) {
			parq_upload_recompute_relative_positions(q);
			q->recompute = FALSE;
		}
	}
}

/**
 * Dump all queued entries before the specified item whose enties have
 * a slot number less than the maximum amount of upload slots we have.
 */
static void
parq_ul_dump_earlier(struct parq_ul_queued *item)
{
	struct parq_ul_queue *q;
	hash_list_iter_t *iter;
	unsigned old_relative = 0;

	parq_ul_queued_check(item);

	q = item->queue;
	parq_ul_queue_check(q);

	iter = hash_list_iterator(q->by_rel_pos);

	while (hash_list_iter_has_next(iter)) {
		struct parq_ul_queued *puq = hash_list_iter_next(iter);

		parq_ul_queued_check(puq);
		g_assert_log(puq->relative_position > old_relative,
			"relative=%u, old=%u", puq->relative_position, old_relative);
		old_relative = puq->relative_position;

		if (
			puq->relative_position >= item->relative_position ||
			puq->relative_position > GNET_PROPERTY(max_uploads)
		)
			break;

		g_debug("[PARQ UL] Q#%d pos=%u, rel=%u, slot<has=%s had=%s> updated=%s"
			" active=%s, quick=%s, alive=%s, flags=0x%x, ID=%s, expire=%s ",
			q->num, puq->position, puq->relative_position,
			puq->has_slot ? "y" : "n", puq->had_slot ? "y" : "n",
			compact_time(delta_time(tm_time(), puq->updated)),
			puq->active_queued ? "y" : "n", puq->quick ? "y" : "n",
			puq->is_alive ? "y" : "n", puq->flags, guid_hex_str(&puq->id),
			timestamp_utc_to_string(puq->expire));
	}

	hash_list_iter_release(&iter);
}

/**
 * @return TRUE if the current upload is allowed to get an upload slot.
 */
static bool
parq_upload_continue(struct parq_ul_queued *puq)
{
	plist_t *l = NULL;
	int slots_free;
	bool quick_allowed = FALSE;
	g_assert(puq != NULL);

	/*
	 * A "frozen" entry is an entry still in the queue but removed from the
	 * "by_rel_pos" list because it has concurrent uploads from the same
	 * address and its its max number of uploads per IP.
	 *
	 * Such an entry gets higher retry time and expiration times, and only
	 * when one upload from that IP will be ended can we unfreeze all the
	 * entries for the IP and let the compete again in the queues.
	 *		--RAM, 2007-08-18
	 */

	if (puq->flags & PARQ_UL_FROZEN) {
		if (GNET_PROPERTY(parq_debug) >= 5)
			g_debug("[PARQ UL] %s: "
				"frozen entry, IP %s has %d entr%s uploading (max %u)",
				G_STRFUNC, host_addr_to_string(puq->by_addr->addr),
				puq->by_addr->uploading, plural_y(puq->by_addr->uploading),
				GNET_PROPERTY(max_uploads_ip));

		/*
		 * Maybe the max_uploads_ip setting changed since last time we froze
		 * the entry?  If so, unfreeze them all now and proceed.
		 */

		if (UNSIGNED(puq->by_addr->uploading) >= GNET_PROPERTY(max_uploads_ip))
			return FALSE;		/* No quick upload slot either */

		parq_upload_unfreeze_all(puq);
		/* FALL THROUGH */
	}

	slots_free = free_upload_slots(puq->queue);

	if (slots_free <= 0) {
		/*
		 * If there are no free upload slots the queued upload isn't allowed an
		 * upload slot anyway. So we might just as well abort here.
		 */
		goto check_quick;
	}

	/*
	 * Don't allow more than max_uploads_ip per single host (IP)
	 */
	if (UNSIGNED(puq->by_addr->uploading) >= GNET_PROPERTY(max_uploads_ip)) {
		if (GNET_PROPERTY(parq_debug) >= 5)
			g_debug("[PARQ UL] %s: "
				"max_uploads_ip per single host reached %d/%d",
				G_STRFUNC, puq->by_addr->uploading,
				GNET_PROPERTY(max_uploads_ip));
		parq_upload_freeze_all(puq);
		goto check_quick;
	}

	/*
	 * If the number of upload slots have been decreased, an old queue
	 * may still exist. What to do with those uploads? Should we make
	 * sure those uploads are served first? Those uploads should take
	 * less time to upload anyway, as they _must_ be smaller.
	 */

	l = plist_last(ul_parqs);
	{
		struct parq_ul_queue *queue = l->data;
		if (!queue->active && queue->alive - queue->frozen > 0) {
			if (puq->queue->active) {
				if (GNET_PROPERTY(parq_debug))
					g_debug("[PARQ UL] %s: upload in inactive queue #%d first",
						G_STRFUNC, queue->num);
				goto check_quick;
			}
		}
	}

	/*
	 * Check if current upload may have this slot
	 *
	 * That is when the current upload is the first upload in its
	 * queue which has no upload slot. Or if a earlier queued item is
	 * already downloading something in another queue.
	 */

	if (puq->relative_position <= UNSIGNED(slots_free)) {
		if (GNET_PROPERTY(parq_debug))
			g_debug("[PARQ UL] [#%d] allowing %supload \"%s\" from %s (%s), "
				"relative pos = %u [%s]",
				puq->queue->num,
				puq->active_queued ? "actively queued " : "",
				puq->u->name,
				host_addr_port_to_string(
					puq->u->socket->addr, puq->u->socket->port),
				upload_vendor_str(puq->u),
				puq->relative_position, guid_hex_str(&puq->id));

		return TRUE;
	}

	if (GNET_PROPERTY(parq_debug) > 1) {
		g_debug("[PARQ UL] [#%d] not allowing regular for \"%s\""
			" from %s (%s) pos=%u, rel=%u",
			puq->queue->num, puq->u->name,
			host_addr_port_to_string(
				puq->u->socket->addr, puq->u->socket->port),
			upload_vendor_str(puq->u), puq->position,
			puq->relative_position);

		if (GNET_PROPERTY(parq_debug) > 5)
			parq_ul_dump_earlier(puq);
	}

check_quick:
	/*
	 * Let the download continue if the request is small enough though.
	 * This check must be done only when we would otherwise refuse a
	 * normal slot for this upload.  Indeed, when its quota is exhausted,
	 * it will be queued back.
	 */

	quick_allowed = parq_upload_quick_continue(puq);

	/*
	 * If uploads are stalling, we're already short in bandwidth.  Don't
	 * add to the clogging of the output link.
	 */

	if (GNET_PROPERTY(uploads_stalling) && quick_allowed) {
		if (GNET_PROPERTY(parq_debug))
			g_debug("[PARQ UL] [#%d] no quick upload of %ld bytes (stalling)",
				puq->queue->num, (ulong) puq->chunk_size);
		quick_allowed = FALSE;
	}

	if (quick_allowed) {
		if (GNET_PROPERTY(parq_debug))
			g_debug("[PARQ UL] [#%d] allowed quick upload (%ld bytes)",
				puq->queue->num, (ulong) puq->chunk_size);

		parq_upload_unfreeze_one(puq);
		gnet_prop_incr_guint32(PROP_UL_QUICK_RUNNING);
		gnet_stats_inc_general(GNR_PARQ_QUICK_SLOTS_GRANTED);
		puq->quick = TRUE;
		return TRUE;
	}

	return FALSE;
}

void
parq_upload_upload_got_cloned(struct upload *u, struct upload *cu)
{
	struct parq_ul_queued *puq;

	upload_check(u);

	if (u->parq_ul == NULL) {
		g_assert(cu->parq_ul == NULL);
		return;
	}

	g_assert(u->parq_ul != NULL);
	g_assert(cu->parq_ul != NULL);

	puq = parq_upload_find(u);

	if (puq != NULL)
		puq->u = cu;

	u->parq_ul = NULL;

	g_assert(u->parq_ul == NULL);
	g_assert(cu->parq_ul != NULL);
}

/**
 * Makes sure parq doesn't keep any internal reference to the upload structure
 */
void
parq_upload_upload_got_freed(struct upload *u)
{
	struct parq_ul_queued *puq;

	if (u->parq_ul == NULL)
		return;

	puq = parq_upload_find(u);

	/*
	 * If the u->parq_ul exist there must be a reference to an parq
	 * structure. Otherwise something did go wrong.
	 */
	g_assert(puq != NULL);

	puq->u = NULL;
	u->parq_ul = NULL;
}

/**
 * Get a queue slot, either existing or new.
 *
 * @return slot as an opaque handle, NULL if slot cannot be created.
 */
struct parq_ul_queued *
parq_upload_get(struct upload *u, const header_t *header)
{
	struct parq_ul_queued *puq;
	char *buf;

	upload_check(u);
	g_assert(header != NULL);

	/*
	 * Try to locate by ID first. If this fails, try to locate by IP and file
	 * name. We want to locate on ID first as PARQ clients will always supply
	 * the one they got already.
	 */

	puq = parq_upload_find_id(u, header);

	/*
	 * If they supply a valid ID, they are always allowed to proceed even
	 * when switching resources -- a practice that is encouraged anyway
	 * nowadays, even if it can be seen unfair to others.
	 */

	if (puq == NULL)
		puq = parq_upload_find(u);

	if (puq == NULL) {
		/*
		 * Current upload is not queued yet. If the queue isn't full yet,
		 * always add the upload in the queue.
		 */

		if (parq_upload_queue_full(u))
			return NULL;

		puq = parq_upload_create(u);

		g_assert(puq != NULL);

		/*
		 * Remember whether host supports PARQ.
		 */

		buf = header_get(header, "X-Queue");
		if (buf != NULL) {			/* Remote server does support queues */
			unsigned major;
			get_header_version(buf, &major, NULL);
			puq->supports_parq = booleanize(major >= 1);
		}

		if (GNET_PROPERTY(parq_debug) >= 3)
			g_debug("[PARQ UL] Q %d/%d (%3d[%3d]/%3d) "
				"ETA: %s Added: %s '%s' %s",
				puq->queue->num,
				ul_parqs_cnt,
				puq->position,
				puq->relative_position,
				puq->queue->by_position_length,
				short_time_ascii(parq_upload_lookup_eta(u)),
				host_addr_to_string(puq->remote_addr),
				puq->name, guid_hex_str(&puq->id));
	}

	g_assert(puq != NULL);

	/*
	 * Regardless of the amount of simultaneous upload slots a host can get,
	 * a given PARQ ID can only be used once.
	 */

	if (puq->u != NULL && puq->u != u) {
		if (GNET_PROPERTY(parq_debug)) {
			g_warning("[PARQ UL] Request from ip %s (%s), requested a new "
				"upload %s whilst %s is still running",
				host_addr_to_string(u->addr), upload_vendor_str(u), u->name,
				puq->u->name);
		}
		return NULL;
	}

	hash_list_remove(puq->queue->by_date_dead, puq);

	/*
	 * It is possible the client reused its ID for another file name, which is
	 * a valid thing to do. So make sure we have still got the IP and name
	 * in sync
	 */

	parq_upload_update_addr_and_name(puq, u);

	/*
	 * Count SHA-1 resource switches.  We miss switches between special
	 * uploads, which have no SHA-1.
	 */

	if (puq->sha1 != u->sha1)
		gnet_stats_inc_general(GNR_PARQ_SLOT_RESOURCE_SWITCHING);

	/*
	 * Update SHA-1 when they switch resources being asked.
	 */

	if (puq->sha1) {
		if (u->sha1 != puq->sha1) {		/* Both are atoms */
			if (u->sha1)
				atom_sha1_change(&puq->sha1, u->sha1);
			else
				atom_sha1_free_null(&puq->sha1);
		}
	} else if (u->sha1) {
		puq->sha1 = atom_sha1_get(u->sha1);
	}

	if (upload_is_special(u))
		puq->flags |= PARQ_UL_SPECIAL;
	else
		puq->flags &= ~PARQ_UL_SPECIAL;

	if (!puq->is_alive) {
		puq->queue->alive++;
		puq->is_alive = TRUE;
		g_assert(puq->queue->alive > 0);
		g_assert(!hash_list_contains(puq->queue->by_rel_pos, puq));

		/* Re-insert in the relative position list, unless entry is frozen */
		if (!(puq->flags & PARQ_UL_FROZEN)) {
			parq_upload_insert_relative(puq);
			parq_upload_recompute_relative_positions(puq->queue);
			parq_upload_update_eta(puq->queue);
		}
	}

	buf = header_get(header, "X-Queue");

	if (buf != NULL)			/* Remote server does support queues */
		get_header_version(buf, &puq->major, &puq->minor);

	/*
	 * Update listening IP and port information
	 *
	 * Specs 1.0 defined X-Listen-IP, but 1.0.a corrected to X-Node.
	 * Parse both, but only emit X-Node from now on.
	 *		--RAM, 11/05/2003
	 */

	if (puq->major >= 1) {					/* Only if PARQ advertised */
		buf = header_get(header, "X-Node");
		if (buf == NULL)
			buf = header_get(header, "X-Node-IPv6");
		if (buf == NULL)
			buf = header_get(header, "X-Listen-Ip");	/* Case normalized */

		if (buf != NULL) {
			host_addr_t addr;
			uint16 port;

			/*
			 * Update port / IP entries for other queued entries too.
			 *
			 * XXX We should lookup the IP:Port combo. Multiple clients
			 * XXX could be running from the same IP. We shouldn't update those
			 * XXX entries. However, evil clients might abuse this and run from
			 * XXX multiple ports.
			 */

			string_to_host_addr_port(buf, NULL, &addr, &port);

			if (host_is_valid(addr, port)) {
				plist_t *l = NULL;

				PLIST_FOREACH(puq->by_addr->list, l) {
					struct parq_ul_queued *uq = l->data;
					uq->addr = addr;
					uq->port = port;
					uq->flags &= ~PARQ_UL_NOQUEUE;
				}
			}
		}
	}

	/*
	 * Save pointer to structure. Don't forget to move it to
     * the cloned upload or remove the pointer when the struct
     * is freed
	 */

	puq->u = u;

	return puq;
}

/**
 * Bad bad client, re-requested within the Retry-After interval...
 * See whether we can nonetheless be nice or whether this is abuse.
 *
 * @return TRUE if we can allow the request, FALSE if we detected abuse.
 */
static bool
parq_upload_abusing(
	struct upload *u, struct parq_ul_queued *puq,
	time_t now, time_t org_retry)
{
	gnet_stats_inc_general(GNR_PARQ_RETRY_AFTER_VIOLATION);

	if (
		delta_time(puq->ban_timeout, now) > 0 &&
		GNET_PROPERTY(parq_ban_bad_maxcountwait) != 0
	)
		puq->ban_countwait++;

	if (GNET_PROPERTY(parq_debug)) g_warning("[PARQ UL] "
		"host %s (%s) re-requested \"%s\" too soon (%s early, warn #%u)",
		host_addr_port_to_string(u->socket->addr, u->socket->port),
		upload_vendor_str(u),
		u->name, short_time_ascii(delta_time(org_retry, now)),
		puq->ban_countwait);

	if (
		delta_time(puq->ban_timeout, now) > 0 &&
		puq->ban_countwait >= GNET_PROPERTY(parq_ban_bad_maxcountwait)
	) {
		/*
		 * Bye bye, the client did it again, and is removed from the PARQ
		 * queue now.
		 */

		gnet_stats_inc_general(GNR_PARQ_RETRY_AFTER_KICK_OUT);

		if (GNET_PROPERTY(parq_debug)) g_warning(
			"[PARQ UL] "
			"punishing %s (%s) for re-requesting \"%s\" %s early [%s]",
			host_addr_port_to_string(u->socket->addr, u->socket->port),
			upload_vendor_str(u),
			u->name, short_time_ascii(delta_time(org_retry, now)),
			guid_hex_str(&puq->id));

		parq_add_banned_source(u->addr, delta_time(puq->retry, now));
		parq_upload_force_remove(u);
		return TRUE;
	}

	puq->ban_timeout = time_advance(now, parq_upload_ban_window);

	return FALSE;	/* Process request nonetheless for this time */
}

/**
 * If the download may continue, true is returned. False otherwise (which
 * probably means the upload is queued).
 * Where parq_upload_request honours the number of upload slots, this one
 * is used for dynamic slot allocation.
 * This function expects that the upload was checked with parq_upload_request
 * first.
 */
bool
parq_upload_request_force(struct upload *u, struct parq_ul_queued *handle)
{
	struct parq_ul_queued *puq = handle_to_queued(handle);

	/*
	 * Check whether the current upload is allowed to get an upload slot. If so
	 * move other queued items after the current item up one position in the
	 * queue
	 */
	if (GNET_PROPERTY(max_uploads) > GNET_PROPERTY(ul_running)) {
		/* Again no!. We are not out of upload slots yet. So there is no reason
		 * to let it continue now */
		return FALSE;
	}
	if (parq_upload_continue(puq)) {
		if (u->status == GTA_UL_QUEUED) {
			u->status = GTA_UL_SENDING;
		}
		gnet_stats_inc_general(GNR_PARQ_SLOT_LIMIT_OVERRIDES);
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Update amount downloaded by requestor.
 */
void
parq_upload_update_downloaded(const struct upload *u)
{
	struct parq_ul_queued *puq;

	puq = handle_to_queued(u->parq_ul);

	if (u->downloaded <= puq->file_size)
		puq->downloaded = u->downloaded;
}

/**
 * @return If the download may continue, TRUE is returned. FALSE otherwise
 * (which probably means the upload is queued).
 */
bool
parq_upload_request(struct upload *u)
{
	struct parq_ul_queued *puq;
	time_t now, org_retry;

	upload_check(u);

	puq = handle_to_queued(u->parq_ul);
	org_retry = puq->retry;
	now = tm_time();

	puq->chunk_size = u->skip > u->end ? 0 : u->end - u->skip + 1;
	puq->updated = now;
	puq->retry = time_advance(now, parq_ul_calc_retry(puq));

	g_assert(delta_time(puq->retry, now) >= 0);

	puq->expire = time_advance(puq->retry, MIN_LIFE_TIME + PARQ_RETRY_SAFETY);

	if (GNET_PROPERTY(parq_debug) > 1)
		g_debug("[PARQ UL] %srequest for \"%s\" from %s <%s>: %s, "
			"chunk=%s, now=%lu, retry=%lu, expire=%lu, quick=%s, has_slot=%s, "
			"uploaded=%s id=%s",
			puq->supports_parq ? "PARQ-" : "",
			u->name, host_addr_to_string(u->addr),
			upload_vendor_str(u),
			puq->active_queued ?
				"active" : puq->has_slot ?
				"running" : "passive",
			uint64_to_string(puq->chunk_size),
			(unsigned long) now,
			(unsigned long) puq->retry,
			(unsigned long) puq->expire,
			puq->quick ? "y" : "n",
			puq->has_slot ? "y" : "n",
			filesize_to_string(puq->uploaded_size),
			guid_hex_str(&puq->id));

	/*
	 * Make sure they did not retry the request too soon.
	 * This check is naturally skipped for follow-up requests.
	 *
	 * Be nice however if they only request a few seconds too early.
	 */

	if (
		!puq->has_slot &&		/* Not a follow-up request */
		delta_time(org_retry, now) >= PARQ_MIN_POLL
	) {
		if (
			!(
				(puq->flags & PARQ_UL_QUEUE_SENT) ||
				u->status == GTA_UL_QUEUE_WAITING
			) && parq_upload_abusing(u, puq, now, org_retry)
		)
			return FALSE;
	} else {
		if (puq->ban_countwait > 0)
				puq->ban_countwait--;		/* They requested on time */
	}

	/*
	 * If we sent a QUEUE message and we're getting a reply, reset the
	 * amount of QUEUE messages sent and clear the flag.
	 */

	if (puq->flags & PARQ_UL_QUEUE_SENT) {
		puq->queue_sent = 0;
		puq->flags &= ~PARQ_UL_QUEUE_SENT;
		gnet_stats_inc_general(GNR_PARQ_QUEUE_FOLLOW_UPS);
	}

	/*
	 * Client was already downloading a segment, segment was finished and
	 * just did a follow up request.  However, if the slot was granted
	 * for a quick upload, and the amount requested is too large now,
	 * we cannot allow it to continue.
	 */

	if (puq->has_slot) {
		if (!puq->quick) {
			g_assert(puq->relative_position == 0);
			return TRUE;			/* Has regular slot */
		}
		if (parq_upload_quick_continue(puq)) {
			g_assert(puq->relative_position > 0);
			return TRUE;			/* Has quick slot */
		}
		if (GNET_PROPERTY(parq_debug))
			g_debug("[PARQ UL] Fully checking quick upload slot");
		/* FALL THROUGH */
	}

	if (puq->quick) {
		gnet_prop_decr_guint32(PROP_UL_QUICK_RUNNING);
		puq->quick = FALSE;		/* Doing full "continue" checks now */
	}

	/*
	 * Check whether the current upload is allowed to get an upload slot. If so
	 * move other queued items after the current item up one position in the
	 * queue
	 */

	if (parq_upload_continue(puq))
		return TRUE;

	if (puq->has_slot) {
		/*
		 * This was a quick slot (or we'd have returned TRUE above already
		 * if we had a regular slot).  Therefore, don't do a
		 *
		 *		puq->queue->active_uploads--;
		 *
		 * since this is only incremented for non-quick uploads: quick slots
		 * are only a graceful answer we give, and they are transient.
		 *		--RAM, 2007-08-17
		 */

		g_assert(puq->relative_position > 0);	/* Was a quick slot */

		puq->by_addr->uploading--;
		puq->has_slot = FALSE;
		parq_upload_unfreeze_all(puq);	/* Allow others to compete */
	}

	/*
	 * Check whether we should actively queue this upload.
	 */
	if (puq->active_queued) {
		enum fd_avail_status fds = fd_avail_status();

		/*
		 * Status is changed by upload_request(), so we must make sure
		 * we reset the status to "actively queued" if we want to keep
		 * this connection actively queued.
		 *
		 * When we're running out of file descriptors, we severely limit
		 * the amount of actively queued entries and can turn active queueing
		 * into passive queuing.  This should not hurt PARQ-aware peers, unless
		 * they contacted us via a PUSH, in which case we need to be nicer.
		 *		--RAM, 2007-09-08
		 */

		switch (fds) {
		case FD_AVAIL_GREEN:
			u->status = GTA_UL_QUEUED;		/* Maintain active queuing */
			break;
		case FD_AVAIL_YELLOW:
			if (puq->flags & PARQ_UL_FROZEN)
				puq->active_queued = FALSE;
			else if (u->push)
				u->status = GTA_UL_QUEUED;	/* Only for pushed uploads */
			else
				puq->active_queued = FALSE;
			break;
		case FD_AVAIL_RED:
			/* Maintain connection only if almost certain to yield slot soon */
			if (puq->flags & PARQ_UL_FROZEN)
				puq->active_queued = FALSE;
			else if (
				puq->relative_position <=
				1 + UNSIGNED(free_upload_slots(puq->queue)) / 2
			)
				u->status = GTA_UL_QUEUED;	/* Maintain active queuing */
			else
				puq->active_queued = FALSE;
			break;
		}

		if (!puq->active_queued) {
			puq->by_addr->active_queued--;
			puq->queue->active_queued_cnt--;

			if (GNET_PROPERTY(parq_debug))
				g_debug("PARQ UL: [#%d] [%s] "
					"fds=%s, position=%d, push=%s, frozen=%s => "
					"switching from active to passive for %s (%s)",
					puq->queue->num, guid_hex_str(&puq->id),
					fd_avail_status_string(fds),
					puq->relative_position, u->push ? "y" : "n",
					(puq->flags & PARQ_UL_FROZEN) ? "y" : "n",
					host_addr_port_to_string(u->socket->addr, u->socket->port),
					upload_vendor_str(u));
		}
	} else {
		enum fd_avail_status fds = fd_avail_status();
		bool queueable;
		bool activeable = TRUE;
		uint max_slot = parq_upload_active_size +
			GNET_PROPERTY(max_uploads) / 2;
		uint max_fd_used =
			GNET_PROPERTY(max_downloads) +
			GNET_PROPERTY(max_uploads) +
			(settings_is_leaf() ?
				GNET_PROPERTY(max_ultrapeers) :
				(GNET_PROPERTY(max_connections) + GNET_PROPERTY(max_leaves))
			);

		/* Active queue requests which are either a push request and at a
		 * reasonable position. Or if the request is at a position which
		 * might actually get an upload slot soon
		 *
		 * The "queueable" variable makes sure that the total amount of file
		 * descriptors available for this process is larger than the maximum
		 * amout of file descriptors we can use.  This is not accounting ALL
		 * the possible connections we can make, hence the "4/5" corrective
		 * factor.
		 *
		 * Since "max_downloads" is rarely going to be fully utilized, we
		 * correct the numbers if we see it is much bigger than the current
		 * usage.
		 */

		if (GNET_PROPERTY(max_downloads) >= 3 *
			(GNET_PROPERTY(dl_running_count) + GNET_PROPERTY(dl_active_count))
		)
			max_fd_used -= GNET_PROPERTY(max_downloads) / 2;

		queueable = GNET_PROPERTY(sys_nofile) * 4 / 5 >
			max_fd_used + (MIN_ALWAYS_QUEUE * GNET_PROPERTY(max_uploads));

		if (puq->relative_position <= MIN_ALWAYS_QUEUE)
			queueable = TRUE;

		/*
		 * Disable active queueing when under a fd shortage, excepted for
		 * pushed uploads where we still allow them, unless there's a clear
		 * runout in which case we allow them only if they're likely to be
		 * scheduled soon.
		 *		--RAM, 2007-09-08
		 */

		switch (fds) {
		case FD_AVAIL_GREEN:
			break;
		case FD_AVAIL_YELLOW:
			queueable = FALSE;
			activeable = FALSE;
			break;
		case FD_AVAIL_RED:
			max_slot = 1 + UNSIGNED(free_upload_slots(puq->queue)) / 2;
			queueable = FALSE;
			activeable = FALSE;
			break;
		}

		if (
			(u->push && puq->relative_position <= max_slot) ||
			(queueable && puq->relative_position <=
				UNSIGNED(free_upload_slots(puq->queue)) + MIN_UPLOAD_ASLOT)
		) {
			if ((puq->flags & PARQ_UL_FROZEN) && !activeable) {
				if (GNET_PROPERTY(parq_debug))
					g_debug("PARQ UL: [#%d] [%s] "
						"fds=%s, push=%s, frozen=%s => "
						"denying active queueing for %s (%s)",
						puq->queue->num, guid_hex_str(&puq->id),
						fd_avail_status_string(fds), u->push ? "y" : "n",
						(puq->flags & PARQ_UL_FROZEN) ? "y" : "n",
						host_addr_port_to_string(
							u->socket->addr, u->socket->port),
						upload_vendor_str(u));
			} else if (puq->minor > 0 || puq->major > 0) {
				u->status = GTA_UL_QUEUED;
				puq->active_queued = TRUE;
				puq->by_addr->active_queued++;
				puq->queue->active_queued_cnt++;
			}
		}
	}

	u->parq_status = TRUE;		/* XXX would violate encapsulation */
	return FALSE;
}

/**
 * Unmark actively queued upload.
 */
static void
parq_upload_clear_actively_queued(struct parq_ul_queued *puq)
{
	g_assert(puq->by_addr->active_queued > 0);
	puq->by_addr->active_queued--;
	g_assert(puq->queue->active_queued_cnt > 0);
	puq->queue->active_queued_cnt--;

	puq->active_queued = FALSE;
}

/**
 * Mark an upload as really being active instead of just being queued.
 */
void
parq_upload_busy(struct upload *u, struct parq_ul_queued *handle)
{
	struct parq_ul_queued *puq = handle_to_queued(handle);

	upload_check(u);
	g_assert(puq != NULL);

	if (GNET_PROPERTY(parq_debug) > 2) {
		g_debug("PARQ UL [#%d] upload pos=%d rel=%d (%s, %s, %s) "
			"is now busy [%s]",
			puq->queue->num, puq->position, puq->relative_position,
			puq->active_queued ? "active" : "passive",
			puq->has_slot ? "with slot" : "no slot yet",
			puq->quick ? "quick" : "regular",
			guid_hex_str(&puq->id));
	}

	u->parq_status = FALSE;			/* XXX -- get rid of `parq_status'? */

	if (puq->active_queued)
		parq_upload_clear_actively_queued(puq);

	/*
	 * Remove upload from the relative position list since it has a slot.
	 * It will be re-added as slot #1 when the upload is removed, where it
	 * will stay there until it expires.  This allows them to reclaim their
	 * slot in case something weird happens.
	 *
	 * We only do that when the slot is a regular one and not a quick shot,
	 * since quick uploads are bound to be queued anyway.
	 *
	 *		--RAM, 2007-08-16
	 */

	if (!puq->quick && puq->relative_position) {
		parq_upload_remove_relative(puq);
		parq_upload_recompute_relative_positions(puq->queue);

		puq->relative_position = 0;		/* Signals: has regular slot */
		puq->had_slot = TRUE;			/* Had a regular slot */
		puq->queue->active_uploads++;	/* Account active in queue */
	}

	if (puq->has_slot)
		return;

	/* XXX Perhaps it is wise to update the puq->remote_addr here.
	 * XXX However, we should also update the parq_by_addr and all related
	 * XXX uploads.
	 */

	g_assert(puq->by_addr != NULL);
	g_assert(host_addr_equiv(puq->by_addr->addr, puq->remote_addr));

	puq->has_slot = TRUE;
	puq->by_addr->uploading++;
	puq->slot_granted = tm_time();
}

void
parq_upload_add(struct upload *u)
{
	/*
	 * Cosmetic. Not used at the moment. struct upload structure probably
	 * isn't complete yet at this moment
	 */
	upload_check(u);
}

void
parq_upload_force_remove(struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);
	if (puq != NULL && !parq_upload_remove(u, UPLOAD_IS_SENDING(u), TRUE)) {
		parq_upload_free(puq);
	}
}

/**
 * Collect running stats about the completed / removed upload.
 */
void
parq_upload_collect_stats(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);

	/*
	 * Browse host requests have no PARQ data structures associated with them,
	 * so having a completed upload does not necessarily imply there is
	 * something to track at this point.
	 */

	if (!u->parq_ul)
		return;

	/*
	 * Data is only expected to be sent when the upload had a slot
	 */

   	puq = parq_upload_find(u);
	g_assert(puq != NULL);

	puq->uploaded_size += u->sent;
}

/**
 * When an upload is removed this function should be called so parq
 * knows the current upload status of an upload.
 *
 * @return TRUE if the download was totally removed. And the associated memory
 * was cleared. FALSE if the parq structure still exists.
 */
bool
parq_upload_remove(struct upload *u, bool was_sending, bool was_running)
{
	time_t now = tm_time();
	struct parq_ul_queued *puq = NULL;

	upload_check(u);

	/*
	 * We need to clear the "active_queued" flag everytime, in case we
	 * get an EOF from an actively queued upload...  It still has a
	 * u->parq_status field when not running.
	 *
	 * Likewise, we need to manage the amount of "quick" uploads runnings.
	 *		--RAM, 2007-08-16
	 */

	puq = parq_upload_find(u);

	/*
	 * If we can't find the PARQ entry, this is probably a cloned upload.
	 *
	 * If the upload mismatches, then it's probably an error like "Already
	 * downloading this file" and the lookup for the PARQ entry was done
	 * by name only, but the PARQ slot refers to the running upload.
	 */

	if (puq == NULL || puq->u != u)
		return FALSE;

	/*
	 * If the status is still GTA_UL_QUEUE, then we got removed whilst
	 * attempting to connect to the remote server.
	 */

	if (GTA_UL_QUEUE == u->status)
		parq_upload_send_queue_failed(puq);

	if (puq->active_queued)
		parq_upload_clear_actively_queued(puq);

	if (puq->quick) {
		gnet_prop_decr_guint32(PROP_UL_QUICK_RUNNING);
		puq->quick = FALSE;
	}

	parq_upload_collect_stats(u);

	/*
	 * If we're still in the GTA_UL_QUEUE_WAITING state, we did not get any
	 * HTTP request after sending the QUEUE callback.  However, if we sent
	 * a QUEUE request and went further, reset the amount of refused QUEUE.
	 *		--RAM, 17/05/2003
	 */

	if (GNET_PROPERTY(parq_debug) > 2 && (puq->flags & PARQ_UL_QUEUE_SENT))
		g_debug("PARQ UL Q %d/%d: "
			"QUEUE #%d sent [refused=%d], u->status = %d",
			puq->queue->num,
			ul_parqs_cnt,
			puq->queue_sent, puq->queue_refused, u->status);

	if (u->status == GTA_UL_QUEUE_WAITING)
		puq->queue_refused++;
	else if (puq->flags & PARQ_UL_QUEUE_SENT)
		puq->queue_refused = 0;

	/*
	 * Clear QUEUE-related flags, regardless of the outcome on remote servent.
	 */

	if ((puq->flags & PARQ_UL_QUEUE) && !hash_list_contains(ul_parq_queue, puq))
		puq->flags &= ~PARQ_UL_QUEUE;

	puq->flags &= ~PARQ_UL_QUEUE_SENT;

	/*
	 * When the upload was actively queued, the last_update timestamp was
	 * set to somewhere in the future to avoid early removal. However, now we
	 * do want to remove the upload.
	 *
	 * XXX What's this encapsulation breaking? Needed? --RAM, 2007-08-17
	 */

	if (
		u->status == GTA_UL_QUEUED &&
		delta_time(u->last_update, now) > 0
	) {
		u->last_update = puq->updated;
	}

	if (GNET_PROPERTY(parq_debug) > 3)
		g_debug("PARQ UL Q %d/%d [%s]: Upload removed (%s, %s slot) \"%s\"",
			puq->queue->num,
			ul_parqs_cnt, guid_hex_str(&puq->id),
			was_running ? "running" : "waiting",
			puq->has_slot ? "with" : "no",
			u->name);

	/*
	 * If upload was killed whilst sending, then reset the "had_slot" flag
	 * to have the entry persisted again.
	 *		--RAM, 2007-08-16
	 */

	if (was_sending && was_running)
		puq->had_slot = FALSE;		/* Did not get a chance to complete */

	/*
	 * Cleanup its slot if it had one.
	 */

	if (puq->has_slot) {
		hash_list_iter_t *iter;

		if (GNET_PROPERTY(parq_debug) > 2)
			g_debug("PARQ UL: [#%d] [%s] Freed an upload slot%s",
				puq->queue->num,
				guid_hex_str(&puq->id), was_sending ? " sending" : "");

		g_assert(!(puq->flags & PARQ_UL_FROZEN));
		g_assert(puq->by_addr != NULL);
		g_assert(puq->by_addr->uploading > 0);
		g_assert(host_addr_equiv(puq->by_addr->addr,puq->remote_addr));

		puq->by_addr->uploading--;

		/*
		 * Tell next waiting upload that a slot is available, using QUEUE
		 */

		iter = hash_list_iterator(puq->queue->by_rel_pos);

		while (hash_list_iter_has_next(iter)) {
			struct parq_ul_queued *puq_next = hash_list_iter_next(iter);

			parq_ul_queued_check(puq_next);

			if (puq_next->has_slot)
				continue;

			/*
			 * Reach following entry in the waiting queue that has no uploading
			 * slot.  If it is actively queued already, then we just have to
			 * wait for the planned retry.  Otherwise, if we can send a QUEUE
			 * and there is none pending, let the host know that it's next
			 * in the line.
			 */

			g_assert(puq_next->queue->active);		/* Since puq->has_slot */

			if (
				!(puq_next->flags & (PARQ_UL_QUEUE|PARQ_UL_NOQUEUE)) &&
				!puq_next->active_queued
			)
				parq_upload_register_send_queue(puq_next);
			break;
		}

		hash_list_iter_release(&iter);

		/*
		 * Put back in queue until it expires.
		 */

		if (0 == puq->relative_position) {
			puq->queue->active_uploads--;
			puq->expire = time_advance(now, GUARDING_TIME);

			/*
			 *
			 * If the upload is deemed to be complete, prevent the sending
			 * of QUEUE callbacks, until they make a new request at least.
			 */

			if (puq->had_slot)
				puq->flags |= PARQ_UL_NOQUEUE;

			g_assert(!hash_list_contains(puq->queue->by_rel_pos, puq));

			parq_upload_insert_relative(puq);
			parq_upload_recompute_relative_positions(puq->queue);
		}

		parq_upload_unfreeze_all(puq);	/* Allow others to compete */

		/*
		 * Update queue statistics on the amount of time we keep slots.
		 */

		if (puq->slot_granted != 0) {
			time_delta_t kept = delta_time(now, puq->slot_granted);
			struct parq_ul_queue *q = puq->queue;

			while (statx_n(q->slot_stats) >= STAT_POINTS)
				statx_remove_oldest(q->slot_stats);

			statx_add(q->slot_stats, kept);
		}
	}

	g_assert(puq->queue->active_uploads >= 0);

	/*
	 * Avoid removing an upload which is being removed because we are returning
	 * a busy (503), in which case the upload got queued
	 */

	if (u->parq_status) {
		/* This means we called parq_upload_request() which returned FALSE */
		u->parq_status = FALSE;
		goto done;
	}

	if (
		u->status == GTA_UL_ABORTED &&
		puq->has_slot &&
		delta_time(puq->disc_timeout, now) > 0
	) {
		/* Client disconnects too often. This could block our upload
		 * slots. Sorry, but we are going to remove this upload */
		if (u->socket != NULL) {
			g_warning("[PARQ UL] "
				"Removing %s (%s) for too many disconnections \"%s\" "
				"%u secs early",
				host_addr_port_to_string(u->socket->addr, u->socket->port),
				upload_vendor_str(u),
				u->name, (unsigned) delta_time(puq->disc_timeout, now));
		} else {
			g_warning("[PARQ UL] "
				"Removing (%s) for too many disconnections \"%s\" "
				"%u secs early",
				upload_vendor_str(u),
				u->name, (unsigned) delta_time(puq->disc_timeout, now));
		}
		parq_upload_free(puq);
		return TRUE;
	} else {
		/*
		 * A client is not allowed to disconnect over and over again
		 * (ie data write error). Set the time for which a client
		 * should not disconnect
		 */
		if (puq->has_slot)
			puq->disc_timeout = time_advance(now, parq_upload_ban_window/5);

		/* Disconnected upload is allowed to reconnect immediatly */
		puq->retry = now;

		/*
		 * The upload slot expires rather soon to speed up uploading. This
		 * doesn't prevent a broken connection from reconnecting though, it is
		 * just not garanteed anymore that it will regain its upload slot
		 * immediatly
		 */
		puq->expire = time_advance(now, GUARDING_TIME);
	}

done:
	puq->has_slot = FALSE;
	puq->slot_granted = 0;

	return FALSE;
}

static size_t
parq_upload_add_retry_after_header(char *buf, size_t size, uint d)
{
	size_t len;

	len = concat_strings(buf, size,
			"Retry-After: ", uint32_to_string(d), "\r\n",
			NULL_PTR);
	return len < size ? len : 0;
}

static size_t
parq_upload_add_old_queue_header(char *buf, size_t size,
	struct parq_ul_queued *puq, uint min_poll, uint max_poll,
	bool small_reply)
{
	size_t len;

	if (small_reply) {
		len = str_bprintf(buf, size,
				"X-Queue: position=%d, pollMin=%u, pollMax=%u\r\n",
				puq->relative_position, min_poll, max_poll);
	} else {
		len = str_bprintf(buf, size,
				"X-Queue: position=%d, length=%d, "
				"limit=%d, pollMin=%u, pollMax=%u\r\n",
				puq->relative_position, puq->queue->by_position_length,
				1, min_poll, max_poll);
	}
	if (len >= size || (len > 0 && '\n' != buf[len - 1])) {
		return 0;	/* truncated */
	} else {
		return len;
	}
}

static size_t
parq_upload_add_x_queued_header(char *buf, size_t size,
	struct parq_ul_queued *puq, uint max_poll,
	bool small_reply, struct upload *u)
{
	size_t rw = 0, len;

	upload_check(u);

	/* Reserve space for the trailing \r\n */
	if (sizeof "\r\n" >= size)
		return 0;
	size -= sizeof "\r\n";

	len = concat_strings(&buf[rw], size,
			"X-Queued: ID=", guid_hex_str(parq_upload_lookup_id(u)),
			/* No CRLF yet, we're still appending to this header */
			NULL_PTR);

	if (len < size) {
		rw += len;
		size -= len;

		puq->flags |= PARQ_UL_ID_SENT;

		len = concat_strings(&buf[rw], size,
			"; position=", uint32_to_string(puq->relative_position),
			NULL_PTR);

		if (len < size) {
			rw += len;
			size -= len;

			if (!small_reply) {
				len = concat_strings(&buf[rw], size,
					"; lifetime=", uint32_to_string(max_poll),
					NULL_PTR);
				if (len < size) {
					rw += len;
					size -= len;
					len = concat_strings(&buf[rw], size,
						"; length=",
						uint32_to_string(puq->queue->by_position_length),
						NULL_PTR);
					if (len < size) {
						rw += len;
						size -= len;
						len = concat_strings(&buf[rw], size,
							"; ETA=", uint32_to_string(puq->eta),
							NULL_PTR);
						if (len < size) {
							rw += len;
							size -= len;
						}
					}
				}
			}
		}

		len = concat_strings(&buf[rw], sizeof "\r\n",
				"\r\n",
				NULL_PTR);
		rw += len;
	}
	return rw;
}

/**
 * Adds X-Queued status in the HTTP reply header for a queued upload.
 *
 * @param `buf'		is the start of the buffer where the headers are to
 *					be added.
 * @param `size'	length of the buffer.
 * @param `arg'		no brief description.
 * @param `flags'	no brief description.
 * @return The amount of bytes written to buf.
 *
 * @attention
 * NB: Adds a Retry-After field for servents that will not understand PARQ,
 * to make sure they do not re-request too soon.
 */
size_t
parq_upload_add_headers(char *buf, size_t size, void *arg, uint32 flags)
{
	struct parq_ul_queued *puq;
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	bool small_reply;
	time_delta_t d;
	uint min_poll, max_poll;
	time_t now;
	size_t rw = 0;

	upload_check(u);

	if (!parq_upload_queued(u))
		return 0;

	puq = parq_upload_find(u);
	g_return_val_if_fail(puq, 0);

	STATIC_ASSERT(PARQ_MIN_POLL < PARQ_RETRY_SAFETY);

	now = tm_time();
	d = delta_time(puq->retry, now);
	d = MAX(PARQ_MIN_POLL, d);
	d = MIN(d, INT_MAX);
	min_poll = d;

	/*
	 * Give them some time for the max_poll time, to allow for network
	 * transmission delays.
	 */

	d = delta_time(puq->expire, now);
	d -= PARQ_RETRY_SAFETY;
	d = MAX(0, d);
	d = MIN(d, INT_MAX);
	max_poll = d;
	max_poll = MAX(max_poll, min_poll);

	small_reply = 0 != (flags & HTTP_CBF_SMALL_REPLY);

	rw += parq_upload_add_retry_after_header(&buf[rw], size - rw, min_poll);

	if (
		puq->major == 0 &&
		puq->minor == 1 &&
		u->status == GTA_UL_QUEUED
	) {
		rw += parq_upload_add_old_queue_header(&buf[rw], size - rw,
				puq, min_poll, max_poll, small_reply);
	} else {
		rw += parq_upload_add_x_queued_header(&buf[rw], size - rw,
				puq, max_poll, small_reply, u);
	}
	return rw;
}

/**
 * Adds X-Queued status in the HTTP reply header showing the queue ID
 * for an upload getting a slot.
 *
 * @param `buf' is the start of the buffer where the headers are to be added.
 * @param `size' length of 'buf`.
 * @return the amount of bytes written to `buf'.
 */
size_t
parq_upload_add_header_id(char *buf, size_t size, void *arg,
	uint32 unused_flags)
{
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	struct parq_ul_queued *puq;
	size_t rw = 0;

	(void) unused_flags;
	g_assert(buf != NULL);

	upload_check(u);
	puq = parq_upload_find(u);

	g_assert(u->status == GTA_UL_SENDING);
	g_assert(puq != NULL);

	/*
	 * If they understand PARQ, we also give them a queue ID even
	 * when they get an upload slot.  This will allow safe resuming
	 * should the connection be broken while the upload is active.
	 *		--RAM, 17/05/2003
	 */

	if (puq->major >= 1) {
		size_t len;

		len = concat_strings(&buf[rw], size,
				"X-Queued: ID=", guid_hex_str(parq_upload_lookup_id(u)),
				"\r\n",
				NULL_PTR);

		if (len >= size)
			goto finish;

		rw += len;
		size -= len;

		puq->flags |= PARQ_UL_ID_SENT;
	}

finish:
	return rw;
}

/**
 * Determines whether the PARQ ID was already sent for an upload.
 */
bool
parq_ul_id_sent(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);
	return puq != NULL && (puq->flags & PARQ_UL_ID_SENT);
}

/**
 * @return the current queueing position of an upload. Returns a value of
 * (uint) -1 if not found.
 */
uint
parq_upload_lookup_position(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);

	if (puq != NULL) {
		return puq->relative_position;
	} else {
		return (uint) -1;
	}
}

/**
 * @return the current ID of the upload.
 */
const struct guid *
parq_upload_lookup_id(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);
	return puq ? &puq->id : NULL;
}

/**
 * @return the Estimated Time of Arrival for an upload slot for a given upload.
 */
uint
parq_upload_lookup_eta(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);

	/* If puq == NULL the current upload isn't queued and ETA is unknown */
	if (puq != NULL)
		return puq->eta;
	else
		return (uint) -1;
}

/**
 * @return the current upload queue size of alive uploads.
 */
uint
parq_upload_lookup_size(const struct upload *u)
{
	struct parq_ul_queued *puq;

	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */

	upload_check(u);
	puq = parq_upload_find(u);

	if (puq != NULL) {
		g_assert(puq->queue != NULL);
		return puq->queue->alive;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return the lifetime of a queued upload.
 */
time_t
parq_upload_lifetime(const struct upload *u)
{
	struct parq_ul_queued *puq;

	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */

	upload_check(u);
	puq = parq_upload_find(u);

	if (puq != NULL) {
		return puq->expire;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return the time_t at which the next retry is expected.
 */
time_t
parq_upload_retry(const struct upload *u)
{
	struct parq_ul_queued *puq;

	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */

	upload_check(u);
	puq = parq_upload_find(u);

	if (puq != NULL) {
		return puq->retry;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return the queue number the current upload is queued in.
 */
uint
parq_upload_lookup_queue_no(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);

	if (puq != NULL) {
		return puq->queue->num;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/**
 * @return TRUE if the upload was allowed quickly by PARQ.
 */
bool
parq_upload_lookup_quick(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);
	return puq ? puq->quick : FALSE;
}

/**
 * @return TRUE if the upload is frozen.
 */
bool
parq_upload_lookup_frozen(const struct upload *u)
{
	struct parq_ul_queued *puq;

	upload_check(u);
	puq = parq_upload_find(u);
	return (puq && (puq->flags & PARQ_UL_FROZEN)) ? TRUE : FALSE;
}

/**
 * 'Call back' connection was succesfull. So prepare to send headers
 */
void
parq_upload_send_queue_conf(struct upload *u)
{
	char queue[MAX_LINE_SIZE];
	struct parq_ul_queued *puq;
	struct gnutella_socket *s;
	size_t rw;
	ssize_t sent;

	upload_check(u);
	g_assert(u->status == GTA_UL_QUEUE);
	g_assert(u->name);

	puq = parq_upload_find(u);

	g_return_unless(puq != NULL);

	/*
	 * Send the QUEUE header.
	 */

	puq->flags &= ~PARQ_UL_QUEUE;

	rw = str_bprintf(queue, sizeof queue, "QUEUE %s %s\r\n",
			guid_hex_str(&puq->id),
			host_addr_port_to_string(listen_addr(), socket_listen_port()));

	s = u->socket;

	sent = bws_write(BSCHED_BWS_OUT, &s->wio, queue, rw);
	if ((ssize_t) -1 == sent) {
		g_warning("[PARQ UL] "
			"Unable to send back QUEUE for \"%s\" to %s: %m",
			  u->name, host_addr_port_to_string(s->addr, s->port));
	} else if ((size_t) sent < rw) {
		g_warning("[PARQ UL] "
			"Only sent %lu out of %lu bytes of QUEUE for \"%s\" to %s",
			  (ulong) sent, (ulong) rw, u->name,
			  host_addr_port_to_string(s->addr, s->port));
	} else if (GNET_PROPERTY(parq_debug) > 2) {
		g_debug("PARQ UL: Sent #%d to %s: %s",
			  puq->queue_sent, host_addr_port_to_string(s->addr, s->port),
			  queue);
	}

	if ((size_t) sent != rw) {
		upload_remove(u, "Unable to send QUEUE #%d", puq->queue_sent);
		return;
	}

	/*
	 * We sent the QUEUE message.
	 * We're now expecting HTTP headers on the connection we've established
	 */

	puq->flags |= PARQ_UL_QUEUE_SENT;
	gnet_stats_inc_general(GNR_PARQ_QUEUE_SENT);
	expect_http_header(u, GTA_UL_QUEUE_WAITING);
}

/**
 * Saves an individual queued upload to disc.
 *
 * This is the callback function used by plist_foreach() in function
 * parq_upload_save_queue().
 */
static inline void
parq_store(void *data, void *file_ptr)
{
	FILE *f = file_ptr;
	struct parq_ul_queued *puq = data;
	char last_buf[TIMESTAMP_BUFLEN];
	char enter_buf[TIMESTAMP_BUFLEN];
	int expire;

	/* We are not saving uploads which already finished an upload */
	if (puq->had_slot && !puq->has_slot)
		return;

	if (puq->has_slot) {
		/* If we have a slot, puq->expire is meaningless */
		expire = 0;
	} else {
		expire = delta_time(puq->expire, tm_time());
		if (expire < 0)
			return;
	}

	g_assert(NULL != f);
	if (GNET_PROPERTY(parq_debug) > 5) {
		g_debug("PARQ UL Q %d/%d (%3d[%3d]/%3d): Saving %s: '%s' - %s '%s'",
			  puq->queue->num,
			  ul_parqs_cnt,
			  puq->position,
			  puq->relative_position,
			  puq->queue->by_position_length,
			  puq->supports_parq ? "PARQ" : "slot",
			  guid_hex_str(&puq->id),
			  host_addr_to_string(puq->remote_addr),
			  puq->name);
	}

	timestamp_to_string_buf(puq->enter, enter_buf, sizeof enter_buf);
	timestamp_to_string_buf(puq->last_queue_sent, last_buf, sizeof last_buf);

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
		"GOT: %s\n"
		"IP: %s\n"
		,
		puq->queue->num,
		puq->position,
		enter_buf,
		expire,
		guid_hex_str(&puq->id),
		uint64_to_string(puq->file_size),
		uint64_to_string2(puq->downloaded),
		host_addr_to_string(puq->remote_addr)
	);

	if (puq->queue_sent) {
		fprintf(f,
			"QUEUESSENT: %d\n"
			"LASTQUEUE: %s\n"
			,
			puq->queue_sent,
			last_buf
		);
	}

	if (puq->sha1)
		fprintf(f, "SHA1: %s\n", sha1_base32(puq->sha1));

	if (puq->supports_parq)
		fprintf(f, "PARQ:\n");	/* No value needed, tag presence is enough */

	if (
		!(puq->flags & PARQ_UL_NOQUEUE) &&
		puq->port != 0 && is_host_addr(puq->addr)
	) {
		fprintf(f,
			"XIP: %s\n"
			"XPORT: %u\n",
			host_addr_to_string(puq->addr), (unsigned) puq->port);
	}
	fprintf(f, "NAME: %s\n\n", puq->name);
}

/**
 * Saves all the current queues and their items so it can be restored when the
 * client starts up again.
 */
static void
parq_upload_save_queue(void)
{
	FILE *f;
	file_path_t fp;
	time_t now = tm_time();
	plist_t *queues;

	if (GNET_PROPERTY(parq_debug) > 3)
		g_debug("PARQ UL: trying to save all queue info");

	file_path_set(&fp, settings_config_dir(), file_parq_file);
	f = file_config_open_write("PARQ upload queue data", &fp);
	if (!f)
		return;

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n#\n", f);
	fprintf(f, "# Saved on %s\n", timestamp_to_string(now));

	for (
		queues = plist_last(ul_parqs) ; queues != NULL; queues = queues->prev
	) {
		struct parq_ul_queue *queue = queues->data;

		PLIST_FOREACH_CALL_DATA(queue->by_position, parq_store, f);
	}

	file_config_close(f, &fp);

	if (GNET_PROPERTY(parq_debug) > 3)
		g_debug("PARQ UL: all saved");

}

/**
 * Callout queue periodic event to save PARQ queues.
 */
static bool
parq_save_timer(void *unused_udata)
{
	(void) unused_udata;

	if (!parq_is_enabled())
		return TRUE;

	if (GNET_PROPERTY(parq_debug)) {
		plist_t *l;

		PLIST_FOREACH(ul_parqs, l) {
			struct parq_ul_queue *q = l->data;

			g_debug("PARQ UL: Queue %d/%d contains %d items, "
				  "%d uploading, %d alive, queue marked %s",
				  q->num, ul_parqs_cnt, q->by_position_length,
				  q->active_uploads, q->alive,
				  q->active ? "active" : "inactive");
		}
	}

	parq_upload_save_queue();

	return TRUE;		/* Keep calling */
}

typedef enum {
	PARQ_TAG_UNKNOWN = 0,
	PARQ_TAG_ENTERED,
	PARQ_TAG_EXPIRE,
	PARQ_TAG_ID,
	PARQ_TAG_IP,
	PARQ_TAG_NAME,
	PARQ_TAG_PARQ,
	PARQ_TAG_POS,
	PARQ_TAG_QUEUE,
	PARQ_TAG_SHA1,
	PARQ_TAG_SIZE,
	PARQ_TAG_GOT,
	PARQ_TAG_XIP,
	PARQ_TAG_XPORT,
	PARQ_TAG_QUEUESSENT,
	PARQ_TAG_LASTQUEUE,

	NUM_PARQ_TAGS
} parq_tag_t;

static const tokenizer_t parq_tags[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define PARQ_TAG(x) { #x, CAT2(PARQ_TAG_,x) }
	PARQ_TAG(ENTERED),
	PARQ_TAG(EXPIRE),
	PARQ_TAG(GOT),
	PARQ_TAG(ID),
	PARQ_TAG(IP),
	PARQ_TAG(LASTQUEUE),
	PARQ_TAG(NAME),
	PARQ_TAG(PARQ),
	PARQ_TAG(POS),
	PARQ_TAG(QUEUE),
	PARQ_TAG(QUEUESSENT),
	PARQ_TAG(SHA1),
	PARQ_TAG(SIZE),
	PARQ_TAG(XIP),
	PARQ_TAG(XPORT),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef PARQ_TAG
};

static inline parq_tag_t
parq_string_to_tag(const char *s)
{
	return TOKENIZE(s, parq_tags);
}

typedef struct {
	const struct sha1 *sha1;
	filesize_t filesize;
	filesize_t downloaded;
	host_addr_t addr;
	host_addr_t x_addr;
	int queue;
	int pos;
	time_t entered;
	int expire;
	int xport;
	time_t last_queue_sent;
	int queue_sent;
	char name[1024];
	struct guid id;
	unsigned supports_parq:1;
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
	char line[4096];
	bool next = FALSE;
	struct parq_ul_queued *puq;
	time_t now = tm_time();
	uint line_no = 0;
	uint64 v;
	int error;
	const char *endptr;
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_PARQ_TAGS)];
	bool resync = FALSE;

	file_path_set(fp, settings_config_dir(), file_parq_file);
	f = file_config_open_read("PARQ upload queue data", fp, N_ITEMS(fp));
	if (!f)
		return;

	if (GNET_PROPERTY(parq_debug))
		g_debug("[PARQ UL] loading queue information");

	/* Reset state */
	entry = zero_entry;
	bit_array_init(tag_used, NUM_PARQ_TAGS);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *colon;
		bool damaged;
		parq_tag_t tag;

		line_no++;

		damaged = FALSE;
		if (!file_line_chomp_tail(line, sizeof line, NULL)) {
			/*
			 * If the line is too long or unterminated the file is either
			 * corrupt or was manually edited without respecting the
			 * exact format. If we continued, we would read from the
			 * middle of a line which could be the filename or ID.
			 */
			g_warning("%s(): line %u too long or missing newline",
				G_STRFUNC, line_no);
			break;
		}

		/* Skip comments and empty lines */
		if (file_line_is_skipable(line)) {
			resync = FALSE;
			continue;
		}

		/* In resync mode, wait for a comment or blank line */
		if (resync)
			continue;

		colon = strchr(line, ':');
		if (!colon) {
			g_warning("%s(): missing colon in line %u", G_STRFUNC, line_no);
			break;
		}
		*colon = '\0';
		tag_name = line;
		value = &colon[1];

		/*
		 * Because of the file_line_chomp_tail() call above, a tag without
		 * value will not have any space after its name, regardless of whether
		 * it was emitted.  Hence we must explicly check for empty values.
		 *		--RAM, 2012-10-12
		 */

		if (*value) {
			if (*value != ' ') {
				g_warning("%s(): no space after colon, line %u for tag \"%s\"",
					G_STRFUNC, line_no, tag_name);
				break;
			}
			value++;	/* skip blank after colon */
		}

		tag = parq_string_to_tag(tag_name);
		g_assert(UNSIGNED(tag) < NUM_PARQ_TAGS);

		if (PARQ_TAG_UNKNOWN != tag && bit_array_get(tag_used, tag)) {
			g_warning("%s(): ignoring duplicate tag \"%s\" in entry in line %u",
				G_STRFUNC, tag_name, line_no);
			continue;
		}
		bit_array_set(tag_used, tag);

		switch (tag) {
		case PARQ_TAG_IP:
		case PARQ_TAG_XIP:
			{
				host_addr_t addr;

				if (!string_to_host_addr(value, NULL, &addr)) {
					damaged = TRUE;
					g_warning("%s(): tag \"%s\", line %u: "
						"not a valid IP address",
						G_STRFUNC, tag_name, line_no);
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

		case PARQ_TAG_GOT:
			v = parse_uint64(value, &endptr, 10, &error);
			damaged |= error != 0 ||
				(v > UINT_MAX && sizeof entry.downloaded <= 4) ||
				*endptr != '\0';
			entry.downloaded = v;
			break;

		case PARQ_TAG_ID:
			if (!hex_to_guid(value, &entry.id)) {
				damaged = TRUE;
			}
			break;

		case PARQ_TAG_PARQ:
			entry.supports_parq = TRUE;
			break;

		case PARQ_TAG_SHA1:
			{
				if (strlen(value) != SHA1_BASE32_SIZE) {
					damaged = TRUE;
					g_warning("%s(): SHA1 value has wrong length %zu",
						G_STRFUNC, strlen(value));
				} else {
					const struct sha1 *raw;

					raw = base32_sha1(value);
					if (raw) {
						entry.sha1 = atom_sha1_get(raw);
					} else {
						damaged = TRUE;
					}
				}
			}
			break;
		case PARQ_TAG_QUEUESSENT:
			v = parse_uint64(value, &endptr, 10, &error);
			damaged |= error != 0 || v > INT_MAX || *endptr != '\0';
			entry.queue_sent = v;
			break;
		case PARQ_TAG_LASTQUEUE:
			{
				time_t t;

				t = date2time(value, now);
				damaged |= t == (time_t) -1;
				entry.last_queue_sent = t;
			}
			break;
		case PARQ_TAG_NAME:
			if (
				g_strlcpy(entry.name, value,
					sizeof entry.name) >= sizeof entry.name
			) {
				damaged = TRUE;
			} else {
				/* Expect next parq entry, this is the final tag */
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
			g_warning("%s(): damaged PARQ entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				G_STRFUNC, line_no, tag_name, value);

			/* Reset state, discard current record */
			next = FALSE;
			entry = zero_entry;
			bit_array_clear_range(tag_used, 0, NUM_PARQ_TAGS - 1);

			/* Will resync on next blank line */
			resync = TRUE;

			continue;
		}

		if (next) {
			struct upload *fake_upload;

			next = FALSE;

			g_assert(!damaged);
			g_assert(entry.name != NULL);

			/* Fill a fake upload structure */
			fake_upload = upload_alloc();
			fake_upload->file_size = entry.filesize;
			fake_upload->downloaded = entry.downloaded;
			fake_upload->name = entry.name;
			fake_upload->addr = entry.addr;

			puq = parq_upload_create(fake_upload);
			g_assert(puq != NULL);

			/*
			 * Upon restart, give them time to retry before we expire the
			 * slot: add MIN_LIFE_TIME to all expiration times.
			 *		--RAM, 2007-08-18
			 */

			puq->supports_parq = entry.supports_parq;
			puq->enter = entry.entered;
			puq->expire = time_advance(now, MIN_LIFE_TIME + entry.expire);
			puq->addr = entry.x_addr;
			puq->port = entry.xport;
			puq->sha1 = entry.sha1;
			puq->last_queue_sent = entry.last_queue_sent;
			puq->queue_sent = entry.queue_sent;
			puq->send_next_queue =
				parq_upload_next_queue(entry.last_queue_sent, puq);

			/* During parq_upload_create already created an ID for us */
			htable_remove(ul_all_parq_by_id, &puq->id);

			STATIC_ASSERT(sizeof entry.id == sizeof puq->id);
			memcpy(&puq->id, &entry.id, sizeof puq->id);
			htable_insert(ul_all_parq_by_id, &puq->id, puq);

			if (GNET_PROPERTY(parq_debug) > 2) {
				g_debug("PARQ UL Q %d/%d (%3d[%3d]/%3d) ETA: %s "
					"restored: %s%s '%s'",
					puq->queue->num,
					ul_parqs_cnt,
					puq->position,
				 	puq->relative_position,
					puq->queue->by_position_length,
					short_time_ascii(parq_upload_lookup_eta(fake_upload)),
					host_addr_to_string(puq->remote_addr),
					puq->supports_parq ? " (PARQ)" : "",
					puq->name);
			}

			if (host_is_valid(puq->addr, puq->port)) {
				if (GNET_PROPERTY(max_uploads) > 0)
					parq_upload_register_send_queue(puq);
			} else {
				puq->flags |= PARQ_UL_NOQUEUE;
			}

			/* Reset state */
			entry = zero_entry;
			bit_array_clear_range(tag_used, 0, NUM_PARQ_TAGS - 1);
			upload_free(&fake_upload);
		}
	}

	fclose(f);
}

/**
 * @return expiration timestamp if source is banned, or 0 if it isn't banned.
 */
time_t
parq_banned_source_expire(const host_addr_t addr)
{
	const struct parq_banned *banned;

	g_assert(ht_banned_source != NULL);

	banned = hevset_lookup(ht_banned_source, &addr);

	return banned ? banned->expire : 0;
}

bool
parq_is_enabled(void)
{
	return GNET_PROPERTY(parq_enabled) && !parq_closed;
}

/**
 * Initialises the upload queue for PARQ.
 */
void G_COLD
parq_init(void)
{
	TOKENIZE_CHECK_SORTED(parq_tags);

	header_features_add(FEATURES_UPLOADS,
		"queue", PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR);
	header_features_add(FEATURES_DOWNLOADS,
		"queue", PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR);

	ul_all_parq_by_addr_and_name = hikset_create(
		offsetof(struct parq_ul_queued, addr_and_name), HASH_KEY_STRING, 0);
	ul_all_parq_by_addr = hevset_create_any(
		offsetof(struct parq_ul_queued_by_addr, addr),
		host_addr_hash_func, host_addr_hash_func2, host_addr_eq_func);
	ul_all_parq_by_id = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);
	dl_all_parq_by_id = htable_create(HASH_KEY_STRING, 0);

	ht_banned_source = hevset_create_any(
		offsetof(struct parq_banned, addr),
		host_addr_hash_func, host_addr_hash_func2, host_addr_eq_func);
	ul_parq_queue = hash_list_new(NULL, NULL);
	ul_queue_sent = aging_make(QUEUE_HOST_DELAY,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);

	(void) parq_upload_new_queue();

	g_assert(ul_all_parq_by_addr_and_name != NULL);
	g_assert(ul_all_parq_by_id != NULL);
	g_assert(ul_all_parq_by_addr != NULL);
	g_assert(dl_all_parq_by_id != NULL);
	g_assert(ht_banned_source != NULL);

	parq_upload_load_queue();
	parq_start = tm_time();

	parq_dead_timer_ev = cq_periodic_main_add(QUEUE_DEAD_SCAN * 1000,
		parq_dead_timer, NULL);
	parq_save_timer_ev = cq_periodic_main_add(QUEUE_SAVE_PERIOD * 1000,
		parq_save_timer, NULL);
}

/**
 * Saves any queueing information and frees all memory used by PARQ.
 */
void G_COLD
parq_close_pre(void)
{
	plist_t *dl, *queues;
	pslist_t *sl, *to_remove = NULL, *to_removeq = NULL;

	parq_shutdown = TRUE;

	parq_upload_save_queue();
	cq_periodic_remove(&parq_dead_timer_ev);
	cq_periodic_remove(&parq_save_timer_ev);

	PLIST_FOREACH(parq_banned_sources, dl) {
		struct parq_banned *banned = dl->data;

		to_remove = pslist_prepend(to_remove, banned);
	}

	PSLIST_FOREACH(to_remove, sl) {
		struct parq_banned *banned = sl->data;

		parq_del_banned_source(banned->addr);
	}

	pslist_free_null(&to_remove);

	/*
	 * First locate all queued items (dead or alive). And place them in the
	 * 'to be removed' list.
	 */
	for (queues = ul_parqs; queues != NULL; queues = queues->next) {
		struct parq_ul_queue *queue = queues->data;

		PLIST_FOREACH(queue->by_position, dl) {
			struct parq_ul_queued *puq = dl->data;

			if (puq == NULL)
				break;

			puq->by_addr->uploading = 0;

			to_remove = pslist_prepend(to_remove, puq);
		}

		to_removeq = pslist_prepend(to_removeq, queue);
	}

	/* Free all memory used by queued items */
	PSLIST_FOREACH(to_remove, sl) {
		parq_upload_free(sl->data);
	}
	pslist_free_null(&to_remove);

	PSLIST_FOREACH(to_removeq, sl) {
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

	pslist_free_null(&to_removeq);

	hikset_free_null(&ul_all_parq_by_addr_and_name);
	hevset_free_null(&ul_all_parq_by_addr);
	htable_free_null(&ul_all_parq_by_id);
	hevset_free_null(&ht_banned_source);
	plist_free_null(&parq_banned_sources);

	hash_list_free(&ul_parq_queue);
	aging_destroy(&ul_queue_sent);
}

/*
 * Final cleanup, must be called after download_close().
 */
void
parq_close(void)
{
	htable_free_null(&dl_all_parq_by_id);
	parq_closed = TRUE;
}

/* vi: set ts=4 sw=4 cindent: */

