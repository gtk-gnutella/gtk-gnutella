/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Token management.
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

#include "common.h"

#include "token.h"
#include "version.h"
#include "misc.h"
#include "sha1.h"
#include "base64.h"
#include "crc.h"

RCSID("$Id$");

#define TOKEN_CLOCK_SKEW	1800		/* +/- 30 minutes */
#define TOKEN_LIFE			60			/* lifetime of our tokens */
#define TOKEN_BASE64_SIZE	(TOKEN_VERSION_SIZE * 4 / 3)	/* base64 size */
#define LEVEL_SIZE			(2 * G_N_ELEMENTS(token_keys))	/* at most */
#define LEVEL_BASE64_SIZE	(LEVEL_SIZE * 4 / 3 + 3)		/* +2 for == tail */

/*
 * Keys are generated through "od -x /dev/random".
 * There can be up to 2^5 = 32 keys per version.
 */

gchar *keys_092u[] = {
	"0a8b f26f 57a1 aaac 2db3 c66c 9f7d 0b17",
	"b59c 9807 a77c c40f c278 daa3 2389 450d",
	"746f 28cc 8b35 100a f5c4 da9f 9888 06b3",
	"cf94 3375 b81d bd67 abf7 85c8 8a1e cbad",
	"165e 0fb4 c08a b367 c970 9895 0818 0c1b",
	"0920 5d33 c206 948a c2d9 1e07 da78 9661",
	"7bc9 38b5 2c7f d392 8855 13af 245e 4441",
	"d43d 6443 65b0 586e c38a 13ba 7515 cfd7",
	"c208 83af 7b60 bf45 4c15 5fa7 cd58 873f",
	"5c24 a272 2afc 1961 8af0 cf70 1d52 759b",
	"3bbf 1e72 8d13 ca96 386d 13ce c2b2 d7c8",
	"a773 a624 3240 2496 993a 5c18 6d73 16ae",
	"f3d5 d302 10c5 5c69 17c2 15a5 8f29 effb",
	"cf78 0a99 abc3 3295 d419 2121 a473 94bb",
	"559d 7dc9 3c57 276f 0658 d51a dd52 2a77",
	"8db8 81a9 1dc5 ee73 cdfa 97a1 a516 5cac",
};

/* 
 * Describes the keys to use depending on the version.
 */
struct tokkey {
	version_t ver;		/* Version number */
	gchar **keys;		/* Keys to use */
	gint count;			/* Amount of keys defined */
} token_keys[] = {
	{
		{ 0, 92, 0, 'u', 0, 1045868400 },			/* 22/02/2003 */
		keys_092u, G_N_ELEMENTS(keys_092u),
	},
};

/*
 * Token validation errors.
 */

static gchar *tok_errstr[] = {
	"OK",							/* TOK_OK */
	"Bad length",					/* TOK_BAD_LENGTH */
	"Bad timestamp",				/* TOK_BAD_STAMP */
	"Bad key index",				/* TOK_BAD_INDEX */
	"Failed checking",				/* TOK_INVALID */
	"Not base64-encoded",			/* TOK_BAD_ENCODING */
	"Keys not found",				/* TOK_BAD_KEYS */
	"Bad version string",			/* TOK_BAD_VERSION */
	"Version older than expected",	/* TOK_OLD_VERSION */
	"Level not base64-encoded",		/* TOK_BAD_LEVEL_ENCODING */
	"Bad level length",				/* TOK_BAD_LEVEL_LENGTH */
	"Level too short",				/* TOK_SHORT_LEVEL */
	"Level mismatch",				/* TOK_INVALID_LEVEL */
	"Missing level",				/* TOK_MISSING_LEVEL */
};

/*
 * tok_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
gchar *tok_strerror(tok_error_t errnum)
{
	if (errnum < 0 || errnum > G_N_ELEMENTS(tok_errstr))
		return "Invalid error code";

	return tok_errstr[errnum];
}

/*
 * find_tokkey
 *
 * Based on the timestamp, determine the proper token keys to use.
 * Returns NULL if we cannot locate any suitable keys.
 */
static struct tokkey *find_tokkey(time_t now)
{
	time_t adjusted = now - VERSION_ANCIENT_BAN;
	gint i;
	struct tokkey *tk;

	for (i = 0; i < G_N_ELEMENTS(token_keys); i++) {
		tk = &token_keys[i];
		if (tk->ver.timestamp > adjusted)
			return tk;
	}

	return NULL;
}

/*
 * random_key
 *
 * Pickup a key randomly.
 * Returns the key string and the index within the key array into `idx'
 * and the token key structure used in `tkused'.
 */
static gchar *random_key(time_t now, gint *idx, struct tokkey **tkused)
{
	static gboolean warned = FALSE;
	gint random_idx;
	struct tokkey *tk;

	tk = find_tokkey(now);

	if (tk == NULL) {
		if (!warned) {
			g_warning("did not find any token key, version too ancient");
			warned = TRUE;
		}

		tk = &token_keys[0];	/* They'll have problems with their token */
	}

	random_idx = random_value(tk->count - 1);
	*idx = random_idx;
	*tkused = tk;

	return tk->keys[random_idx];
}

/*
 * tok_version
 *
 * Get a version token, base64-encoded.
 * Returns a pointer to static data.
 *
 * NOTE: token versions are only used to identify GTKG servents as such with
 * a higher level of confidence than just reading the version string alone.
 * It is not meant to be used for strict authentication management, since
 * the algorithm and the keys are exposed publicly.
 */
guchar *tok_version(void)
{
	static time_t last_generated = 0;
	static guchar *toklevel = NULL;
	guchar token[TOKEN_BASE64_SIZE + 1];
	guint8 digest[TOKEN_VERSION_SIZE];
	guchar lvldigest[LEVEL_SIZE];
	guchar lvlbase64[LEVEL_BASE64_SIZE + 1];
	time_t now = time(NULL);
	struct tokkey *tk;
	gint idx;
	gchar *key;
	SHA1Context ctx;
	guint8 seed[3];
	guint32 now32;
	gint lvlsize;
	gint klen;
	gint i;

	/*
	 * We don't generate a new token each time, but only every TOKEN_LIFE
	 * seconds.  The clock skew threshold must be greater than twice that
	 * amount, of course.
	 */

	g_assert(TOKEN_CLOCK_SKEW > 2 * TOKEN_LIFE);

	if (now - last_generated < TOKEN_LIFE)
		return toklevel;

	last_generated = now;

	/*
	 * Compute token.
	 */

	key = random_key(now, &idx, &tk);
	seed[0] = random_value(0xff);
	seed[1] = random_value(0xff);
	seed[2] = random_value(0xff) & 0xe0;	/* Upper 3 bits only */
	seed[2] |= idx;							/* Has 5 bits for the index */

	now32 = (guint32) g_htonl((guint32) now);
	memcpy(digest, &now32, 4);
	memcpy(digest + 4, &seed, 3);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, key, strlen(key));
	SHA1Input(&ctx, digest, 7);
	SHA1Input(&ctx, version_string, strlen(version_string));
	SHA1Result(&ctx, digest + 7);

	/*
	 * Compute level.
	 */

	lvlsize = G_N_ELEMENTS(token_keys) - (tk - token_keys);
	now32 = crc32_update_crc(0, digest, TOKEN_VERSION_SIZE);
	klen = strlen(tk->keys[0]);

	for (i = 0; i < lvlsize; i++, tk++) {
		gint j;
		guint32 crc = now32;
		guchar *c = (guchar *) &crc;

		for (j = 0; j < tk->count; j++)
			crc = crc32_update_crc(crc, tk->keys[j], klen);

		crc = g_htonl(crc);
		lvldigest[i*2] = c[0] ^ c[1];
		lvldigest[i*2+1] = c[2] ^ c[3];
	}

	/*
	 * Encode into base64.
	 */

	base64_encode_into(digest, TOKEN_VERSION_SIZE, token, TOKEN_BASE64_SIZE);
	token[TOKEN_BASE64_SIZE] = '\0';

	memset(lvlbase64, 0, sizeof(lvlbase64));
	base64_encode_into(lvldigest, 2 * lvlsize, lvlbase64, LEVEL_BASE64_SIZE);

	if (toklevel != NULL)
		g_free(toklevel);

	toklevel = g_strdup_printf("%s; %s", token, lvlbase64);

	return toklevel;
}

/*
 * tok_version_valid
 *
 * Validate a base64-encoded version token `tokenb64' of `len' bytes.
 * Returns error code, or TOK_OK if token is valid.
 */
tok_error_t tok_version_valid(gchar *version, guchar *tokenb64, gint len)
{
	time_t now = time(NULL);
	time_t stamp;
	guint32 stamp32;
	struct tokkey *tk;
	struct tokkey *rtk;
	gint idx;
	gchar *key;
	SHA1Context ctx;
	guchar lvldigest[1024];
	guint8 token[TOKEN_VERSION_SIZE]; 
	guint8 digest[SHA1HashSize];
	version_t rver;
	guchar *end;
	gint toklen;
	gint lvllen;
	gint lvlsize;
	gint klen;
	gint i;
	guchar *c = (guchar *) &stamp32;

	end = (guchar *) strchr(tokenb64, ';');		/* After 25/02/2003 */
	toklen = end ? (end - tokenb64) : len;

	/*
	 * Verify token.
	 */

	if (toklen != TOKEN_BASE64_SIZE)
		return TOK_BAD_LENGTH;

	if (!base64_decode_into(tokenb64, toklen, token, TOKEN_VERSION_SIZE))
		return TOK_BAD_ENCODING;

	memcpy(&stamp32, token, 4);
	stamp = (time_t) g_ntohl(stamp32);

	/*
	 * Versions before 24/02/2003 did not use network order for timestamp.
	 */

	if (ABS(stamp - now) > TOKEN_CLOCK_SKEW)	/* XXX temporary */
		stamp = (time_t) stamp32;

	if (ABS(stamp - now) > TOKEN_CLOCK_SKEW)
		return TOK_BAD_STAMP;

	tk = find_tokkey(stamp);				/* The keys they used */
	if (tk == NULL)
		return TOK_BAD_KEYS;

	idx = token[6] & 0x1f;					/* 5 bits for the index */
	if (idx >= tk->count)
		return TOK_BAD_INDEX;

	key = tk->keys[idx];

	SHA1Reset(&ctx);
	SHA1Input(&ctx, key, strlen(key));
	SHA1Input(&ctx, token, 7);
	SHA1Input(&ctx, version, strlen(version));
	SHA1Result(&ctx, digest);

	if (0 != memcmp(token + 7, digest, SHA1HashSize))
		return TOK_INVALID;

	if (!version_fill(version, &rver))		/* Remote version */
		return TOK_BAD_VERSION;

	if (version_cmp(&rver, &tk->ver) < 0)
		return TOK_OLD_VERSION;

	/*
	 * Verify level.
	 */

	if (end == NULL) {						/* No level */
		if (rver.timestamp >= 1046127600)	/* 25/02/2003 */
			return TOK_MISSING_LEVEL;
		return TOK_OK;
	}

	lvllen = len - toklen - 2;				/* Forget about "; " */
	end += 2;								/* Skip "; " */

	if (lvllen >= sizeof(lvldigest) || lvllen <= 0)
		return TOK_BAD_LEVEL_LENGTH;

	if (lvllen & 0x3)
		return TOK_BAD_LEVEL_LENGTH;

	lvllen = base64_decode_into(end, lvllen, lvldigest, sizeof(lvldigest));

	if (lvllen == 0 || (lvllen & 0x1))
		return TOK_BAD_LEVEL_ENCODING;
	
	g_assert(lvllen >= 2);
	g_assert((lvllen & 0x1) == 0);

	/*
	 * Only check the highest keys we can check.
	 */

	lvllen /= 2;							/* # of keys held remotely */
	lvlsize = G_N_ELEMENTS(token_keys) - (tk - token_keys);
	lvlsize = MIN(lvllen, lvlsize);

	g_assert(lvlsize >= 1);

	rtk = tk + (lvlsize - 1);				/* Keys at that level */

	stamp32 = crc32_update_crc(0, token, TOKEN_VERSION_SIZE);
	klen = strlen(rtk->keys[0]);

	for (i = 0; i < rtk->count; i++)
		stamp32 = crc32_update_crc(stamp32, rtk->keys[i], klen);

	stamp32 = g_htonl(stamp32);

	lvllen--;								/* Move to 0-based offset */

	if (lvldigest[2*lvllen] != (c[0] ^ c[1]))
		return TOK_INVALID_LEVEL;

	if (lvldigest[2*lvllen+1] != (c[2] ^ c[3]))
		return TOK_INVALID_LEVEL;

	for (i = 0; i < G_N_ELEMENTS(token_keys); i++) {
		rtk = &token_keys[i];
		if (rtk->ver.timestamp > rver.timestamp) {
			rtk--;							/* `rtk' could not exist remotely */
			break;
		}
	}

	if (lvllen < rtk - tk)
		return TOK_SHORT_LEVEL;

	return TOK_OK;
}

