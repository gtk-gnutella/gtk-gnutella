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

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>	/* For ntohl(), htonl() */

#include "common.h"

#include "token.h"
#include "version.h"
#include "misc.h"
#include "sha1.h"
#include "base64.h"
#include "crc.h"
#include "clock.h"

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

static const gchar *keys_092u[] = {
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

static const gchar *keys_092c[] = {
	"0d69 54ec e06a 47c4 ec25 cb35 4f3a ec74",
	"c80f 10cd fbd6 85a9 69ef e724 c519 2997",
	"05e4 401f fd79 0e8e def5 12d6 80a9 53b7",
	"f7f5 ae0b 2649 1441 eab4 562f 9509 c4b7",
	"811e 301f 23d0 7e71 017e d449 6c8c 232f",
	"44f1 2a2b d2da 2313 17df 1a21 635f dea2",
	"200e 7cfe 35fa 5a6a 47fc f79e 81c6 e11c",
	"1f7d 541d 1193 4d44 bd84 fdd6 7659 2573",
	"5db1 b96a 2961 7c83 c254 b19d 75dd 1844",
	"72ff 61c8 8553 ddd1 9a32 24cc 88bb 51fd",
	"664d 87d3 1e30 3778 31a2 da87 2e9d f832",
	"c3d9 6801 e69f cf8d d7c7 4f62 9b80 3438",
	"d2fc 0fad 1340 e47a 3f3e b012 18fe 3ad0",
	"2258 65cf 591c dc58 b68a ac2b d174 fe1d",
	"b6a1 7686 c7f7 9e57 d9e8 6c47 e128 d5c0",
	"c545 7424 1b25 e586 1f94 e119 25af 2862",
	"4fb8 1f55 4a5b 2e21 dc48 9fba 7b5c e381",
	"dfe0 c023 06b6 d236 82f6 5732 40d4 492e",
	"93d6 d989 aa52 3ca0 8a69 a79a 424d b7a3",
	"7257 7cff ac09 668f 3b0e 7d6b fe8a 7e7d",
};

/* 
 * Describes the keys to use depending on the version.
 */
struct tokkey {
	version_t ver;		/* Version number */
	const gchar **keys;	/* Keys to use */
	guint count;		/* Amount of keys defined */
} token_keys[] = {
	/* Keep this array sorted by increasing timestamp */
	{
		{ 0, 92, 0, 'u', 0, 1045868400 },			/* 22/02/2003 */
		keys_092u, G_N_ELEMENTS(keys_092u),
	},
	{
		{ 0, 92, 0, 'c', 0, 1053813600 },			/* 25/05/2003 */
		keys_092c, G_N_ELEMENTS(keys_092c),
	},
};

/*
 * Token validation errors.
 */

static const gchar *tok_errstr[] = {
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
const gchar *tok_strerror(tok_error_t errnum)
{
	if (errnum < 0 || errnum >= G_N_ELEMENTS(tok_errstr))
		return "Invalid error code";

	return tok_errstr[errnum];
}

/*
 * find_tokkey
 *
 * Based on the timestamp, determine the proper token keys to use.
 * Returns NULL if we cannot locate any suitable keys.
 */
static const struct tokkey *find_tokkey(time_t now)
{
	time_t adjusted = now - VERSION_ANCIENT_BAN;
	gint i;
	const struct tokkey *tk;

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
static const gchar *random_key(
	time_t now, guint *idx, const struct tokkey **tkused)
{
	static gboolean warned = FALSE;
	guint random_idx;
	const struct tokkey *tk;

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
 * tok_generate
 *
 * Generate new token for given version string.
 */
static gchar *tok_generate(time_t now, const gchar *version)
{
	gchar token[TOKEN_BASE64_SIZE + 1];
	gchar digest[TOKEN_VERSION_SIZE];
	gchar lvldigest[LEVEL_SIZE];
	gchar lvlbase64[LEVEL_BASE64_SIZE + 1];
	const struct tokkey *tk;
	guint idx;
	const gchar *key;
	SHA1Context ctx;
	guint8 seed[3];
	guint32 now32;
	gint lvlsize;
	gint klen;
	gint i;

	/*
	 * Compute token.
	 */

	key = random_key(now, &idx, &tk);
	seed[0] = random_value(0xff);
	seed[1] = random_value(0xff);
	seed[2] = random_value(0xff) & 0xe0;	/* Upper 3 bits only */
	seed[2] |= idx;							/* Has 5 bits for the index */

	now = clock_loc2gmt(now);				/* As close to GMT as possible */

	now32 = (guint32) htonl((guint32) now);
	memcpy(digest, &now32, 4);
	memcpy(digest + 4, &seed, 3);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, (guint8 *) key, strlen(key));
	SHA1Input(&ctx, (guint8 *) digest, 7);
	SHA1Input(&ctx, (guint8 *) version, strlen(version));
	SHA1Result(&ctx, (guint8 *) digest + 7);

	/*
	 * Compute level.
	 */

	lvlsize = G_N_ELEMENTS(token_keys) - (tk - token_keys);
	now32 = crc32_update_crc(0, digest, TOKEN_VERSION_SIZE);
	klen = strlen(tk->keys[0]);

	for (i = 0; i < lvlsize; i++, tk++) {
		gint j;
		guint32 crc = now32;
		const guchar *c = (const guchar *) &crc;

		for (j = 0; j < tk->count; j++)
			crc = crc32_update_crc(crc, tk->keys[j], klen);

		crc = htonl(crc);
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

	return g_strdup_printf("%s; %s", token, lvlbase64);
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
gchar *tok_version(void)
{
	static time_t last_generated = 0;
	static gchar *toklevel = NULL;
	time_t now = time(NULL);

	/*
	 * We don't generate a new token each time, but only every TOKEN_LIFE
	 * seconds.  The clock skew threshold must be greater than twice that
	 * amount, of course.
	 */

	g_assert(TOKEN_CLOCK_SKEW > 2 * TOKEN_LIFE);

	if (now - last_generated < TOKEN_LIFE)
		return toklevel;

	last_generated = now;

	if (toklevel != NULL)
		g_free(toklevel);

	toklevel = tok_generate(now, version_string);

	return toklevel;
}

/*
 * tok_short_version
 *
 * Get a version token for the short version string, base64-encoded.
 * Returns a pointer to static data.
 */
gchar *tok_short_version(void)
{
	static time_t last_generated = 0;
	static gchar *toklevel = NULL;
	time_t now = time(NULL);

	/*
	 * We don't generate a new token each time, but only every TOKEN_LIFE
	 * seconds.  The clock skew threshold must be greater than twice that
	 * amount, of course.
	 */

	g_assert(TOKEN_CLOCK_SKEW > 2 * TOKEN_LIFE);

	if (now - last_generated < TOKEN_LIFE)
		return toklevel;

	last_generated = now;

	if (toklevel != NULL)
		g_free(toklevel);

	toklevel = tok_generate(now, version_short_string);

	return toklevel;
}

/*
 * tok_version_valid
 *
 * Validate a base64-encoded version token `tokenb64' of `len' bytes.
 * The `ip' is given only for clock update operations.
 *
 * Returns error code, or TOK_OK if token is valid.
 */
tok_error_t tok_version_valid(
	const gchar *version, const gchar *tokenb64, gint len, guint32 ip)
{
	time_t now = time(NULL);
	time_t stamp;
	guint32 stamp32;
	const struct tokkey *tk;
	const struct tokkey *rtk;
	guint idx;
	const gchar *key;
	SHA1Context ctx;
	gchar lvldigest[1024];
	gchar token[TOKEN_VERSION_SIZE]; 
	gchar digest[SHA1HashSize];
	version_t rver;
	gchar *end;
	gint toklen;
	gint lvllen;
	gint lvlsize;
	gint klen;
	gint i;
	gchar *c = (gchar *) &stamp32;

	end = strchr(tokenb64, ';');		/* After 25/02/2003 */
	toklen = end ? (end - tokenb64) : len;

	/*
	 * Verify token.
	 */

	if (toklen != TOKEN_BASE64_SIZE)
		return TOK_BAD_LENGTH;

	if (!base64_decode_into(tokenb64, toklen, token, TOKEN_VERSION_SIZE))
		return TOK_BAD_ENCODING;

	memcpy(&stamp32, token, 4);
	stamp = (time_t) ntohl(stamp32);

	/*
	 * Use that stamp, whose precision is TOKEN_LIFE, to update our
	 * clock skew if necessary.
	 */

	clock_update(stamp, TOKEN_LIFE, ip);

	if (ABS(stamp - clock_loc2gmt(now)) > TOKEN_CLOCK_SKEW)
		return TOK_BAD_STAMP;

	tk = find_tokkey(stamp);				/* The keys they used */
	if (tk == NULL)
		return TOK_BAD_KEYS;

	idx = (guchar) token[6] & 0x1f;					/* 5 bits for the index */
	if (idx >= tk->count)
		return TOK_BAD_INDEX;

	key = tk->keys[idx];

	SHA1Reset(&ctx);
	SHA1Input(&ctx, (guint8 *) key, strlen(key));
	SHA1Input(&ctx, (guint8 *) token, 7);
	SHA1Input(&ctx, (guint8 *) version, strlen(version));
	SHA1Result(&ctx, (guint8 *) digest);

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

	stamp32 = htonl(stamp32);

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

