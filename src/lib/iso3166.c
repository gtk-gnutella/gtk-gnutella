/*
 * Copyright (c) 2004, Christian Biere
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
 * Support for mapping ISO 3166 2-letter codes and country names.
 *
 * @author Christian Biere
 * @date 2004
 */

#include "common.h"

#include "ascii.h"
#include "atoms.h"
#include "iso3166.h"
#include "parse.h"

#include "override.h"       /* Must be the last header included */

typedef struct {
	const char *country;	/* atom */
	char cc[3];
} iso3166_entry_t;

/**
 * Suggestion for translators: Translate only the name the of country in
 * which the language is spoken - if the native name is different.
 */

static const struct {
	const char cc[3];
	const char *country;
} iso3166_tab[] = {
	{ "a1", N_("Anonymizing proxies") }, /* Not ISO 3166 */
	{ "a2", N_("Satellite providers") }, /* Not ISO 3166 */
	{ "ad", N_("Andorra") },
	{ "ae", N_("United Arab Emirates") },
	{ "af", N_("Afghanistan") },
	{ "ag", N_("Antigua and Barbuda") },
	{ "ai", N_("Anguilla") },
	{ "al", N_("Albania") },
	{ "am", N_("Armenia") },
	{ "an", N_("Netherlands Antilles") },
	{ "ao", N_("Angola") },
	{ "ap", N_("Asia/Pacific Region") }, /* Not ISO 3166 */
	{ "aq", N_("Antarctica") },
	{ "ar", N_("Argentina") },
	{ "as", N_("American Samoa") },
	{ "at", N_("Austria") },
	{ "au", N_("Australia") },
	{ "aw", N_("Aruba") },
	{ "ax", N_("\xc3\x85land Islands") },
	{ "az", N_("Azerbaijan") },
	{ "ba", N_("Bosnia and Herzegovina") },
	{ "bb", N_("Barbados") },
	{ "bd", N_("Bangladesh") },
	{ "be", N_("Belgium") },
	{ "bf", N_("Burkina Faso") },
	{ "bg", N_("Bulgaria") },
	{ "bh", N_("Bahrain") },
	{ "bi", N_("Burundi") },
	{ "bj", N_("Benin") },
	{ "bl", N_("Saint Barthelemy") },
	{ "bm", N_("Bermuda") },
	{ "bn", N_("Brunei Darussalam") },
	{ "bo", N_("Bolivia") },
	{ "bq", N_("Bonaire, Sint Eustatius and Saba") },
	{ "br", N_("Brazil") },
	{ "bs", N_("Bahamas") },
	{ "bt", N_("Bhutan") },
	{ "bu", N_("Burma") },					/* deprecated */
	{ "bv", N_("Bouvet Island") },
	{ "bw", N_("Botswana") },
	{ "by", N_("Belarus") },
	{ "bz", N_("Belize") },
	{ "ca", N_("Canada") },
	{ "cc", N_("Cocos (Keeling) Islands") },
	{ "cd", N_("Congo (Democratic Republic)") },
	{ "cf", N_("Central African Republic") },
	{ "cg", N_("Congo") },
	{ "ch", N_("Switzerland") },
	{ "ci", N_("Cote d'Ivoire") },
	{ "ck", N_("Cook Islands") },
	{ "cl", N_("Chile") },
	{ "cm", N_("Cameroon") },
	{ "cn", N_("China") },
	{ "co", N_("Colombia") },
	{ "cr", N_("Costa Rica") },
	{ "cs", N_("Serbia and Montenegro") },	/* deprecated */
	{ "cu", N_("Cuba") },
	{ "cv", N_("Cape Verde") },
	{ "cw", N_("Curacao") },
	{ "cx", N_("Christmas Island") },
	{ "cy", N_("Cyprus") },
	{ "cz", N_("Czech Republic") },
	{ "de", N_("Germany") },
	{ "dj", N_("Djibouti") },
	{ "dk", N_("Denmark") },
	{ "dm", N_("Dominica") },
	{ "do", N_("Dominican Republic") },
	{ "dz", N_("Algeria") },
	{ "ec", N_("Ecuador") },
	{ "ee", N_("Estonia") },
	{ "eg", N_("Egypt") },
	{ "eh", N_("Western Sahara") },
	{ "er", N_("Eritrea") },
	{ "es", N_("Spain") },
	{ "et", N_("Ethiopia") },
	{ "eu", N_("Europe") }, /* Not ISO 3166 */
	{ "fi", N_("Finland") },
	{ "fj", N_("Fiji") },
	{ "fk", N_("Falkland Islands (Malvinas)") },
	{ "fm", N_("Micronesia") },
	{ "fo", N_("Faroe Islands") },
	{ "fr", N_("France") },
	{ "ga", N_("Gabon") },
	{ "gb", N_("United Kingdom") },
	{ "gd", N_("Grenada") },
	{ "ge", N_("Georgia") },
	{ "gf", N_("French Guiana") },
	{ "gg", N_("Guernsey") },
	{ "gh", N_("Ghana") },
	{ "gi", N_("Gibraltar") },
	{ "gl", N_("Greenland") },
	{ "gm", N_("Gambia") },
	{ "gn", N_("Guinea") },
	{ "gp", N_("Guadeloupe") },
	{ "gq", N_("Equatorial Guinea") },
	{ "gr", N_("Greece") },
	{ "gs", N_("South Georgia and The South Sandwich Islands") },
	{ "gt", N_("Guatemala") },
	{ "gu", N_("Guam") },
	{ "gw", N_("Guinea-Bissau") },
	{ "gy", N_("Guyana") },
	{ "hk", N_("Hong Kong") },
	{ "hm", N_("Heard Island and McDonald Islands") },
	{ "hn", N_("Honduras") },
	{ "hr", N_("Croatia") },
	{ "ht", N_("Haiti") },
	{ "hu", N_("Hungary") },
	{ "id", N_("Indonesia") },
	{ "ie", N_("Ireland") },
	{ "il", N_("Israel") },
	{ "im", N_("Isle of Man") },
	{ "in", N_("India") },
	{ "io", N_("British Indian Ocean Territory") },
	{ "iq", N_("Iraq") },
	{ "ir", N_("Iran") },
	{ "is", N_("Iceland") },
	{ "it", N_("Italy") },
	{ "je", N_("Jersey") },
	{ "jm", N_("Jamaica") },
	{ "jo", N_("Jordan") },
	{ "jp", N_("Japan") },
	{ "ke", N_("Kenya") },
	{ "kg", N_("Kyrgyzstan") },
	{ "kh", N_("Cambodia") },
	{ "ki", N_("Kiribati") },
	{ "km", N_("Comoros") },
	{ "kn", N_("Saint Kitts and Nevis") },
	{ "kp", N_("North Korea") },
	{ "kr", N_("South Korea") },
	{ "kw", N_("Kuwait") },
	{ "ky", N_("Cayman Islands") },
	{ "kz", N_("Kazakhstan") },
	{ "la", N_("Laos") },
	{ "lb", N_("Lebanon") },
	{ "lc", N_("Saint Lucia") },
	{ "li", N_("Liechtenstein") },
	{ "lk", N_("Sri Lanka") },
	{ "lr", N_("Liberia") },
	{ "ls", N_("Lesotho") },
	{ "lt", N_("Lithuania") },
	{ "lu", N_("Luxembourg") },
	{ "lv", N_("Latvia") },
	{ "ly", N_("Libyan Arab Jamahiriya") },
	{ "ma", N_("Morocco") },
	{ "mc", N_("Monaco") },
	{ "md", N_("Moldova") },
	{ "me", N_("Montenegro") },
	{ "mf", N_("Saint Martin") },
	{ "mg", N_("Madagascar") },
	{ "mh", N_("Marshall Islands") },
	{ "mk", N_("Macedonia") },
	{ "ml", N_("Mali") },
	{ "mm", N_("Myanmar") },
	{ "mn", N_("Mongolia") },
	{ "mo", N_("Macao") },
	{ "mp", N_("Northern Mariana Islands") },
	{ "mq", N_("Martinique") },
	{ "mr", N_("Mauritania") },
	{ "ms", N_("Montserrat") },
	{ "mt", N_("Malta") },
	{ "mu", N_("Mauritius") },
	{ "mv", N_("Maldives") },
	{ "mw", N_("Malawi") },
	{ "mx", N_("Mexico") },
	{ "my", N_("Malaysia") },
	{ "mz", N_("Mozambique") },
	{ "na", N_("Namibia") },
	{ "nc", N_("New Caledonia") },
	{ "ne", N_("Niger") },
	{ "nf", N_("Norfolk Island") },
	{ "ng", N_("Nigeria") },
	{ "ni", N_("Nicaragua") },
	{ "nl", N_("Netherlands") },
	{ "no", N_("Norway") },
	{ "np", N_("Nepal") },
	{ "nr", N_("Nauru") },
	{ "nu", N_("Niue") },
	{ "nz", N_("New Zealand") },
	{ "om", N_("Oman") },
	{ "pa", N_("Panama") },
	{ "pe", N_("Peru") },
	{ "pf", N_("French Polynesia") },
	{ "pg", N_("Papua New Guinea") },
	{ "ph", N_("Philippines") },
	{ "pk", N_("Pakistan") },
	{ "pl", N_("Poland") },
	{ "pm", N_("Saint Pierre and Miquelon") },
	{ "pn", N_("Pitcairn") },
	{ "pr", N_("Puerto Rico") },
	{ "ps", N_("Palestinian Territory") },
	{ "pt", N_("Portugal") },
	{ "pw", N_("Palau") },
	{ "py", N_("Paraguay") },
	{ "qa", N_("Qatar") },
	{ "re", N_("Reunion") },
	{ "ro", N_("Romania") },
	{ "rs", N_("Serbia") },
	{ "ru", N_("Russian Federation") },
	{ "rw", N_("Rwanda") },
	{ "sa", N_("Saudi Arabia") },
	{ "sb", N_("Solomon Islands") },
	{ "sc", N_("Seychelles") },
	{ "sd", N_("Sudan") },
	{ "se", N_("Sweden") },
	{ "sg", N_("Singapore") },
	{ "sh", N_("Saint Helena") },
	{ "si", N_("Slovenia") },
	{ "sj", N_("Svalbard and Jan Mayen") },
	{ "sk", N_("Slovakia") },
	{ "sl", N_("Sierra Leone") },
	{ "sm", N_("San Marino") },
	{ "sn", N_("Senegal") },
	{ "so", N_("Somalia") },
	{ "sr", N_("Suriname") },
	{ "ss", N_("South Sudan") },
	{ "st", N_("Sao Tome and Principe") },
	{ "sv", N_("El Salvador") },
	{ "sx", N_("Sint Maarten") },
	{ "sy", N_("Syrian Arab Republic") },
	{ "sz", N_("Swaziland") },
	{ "tc", N_("Turks and Caicos Islands") },
	{ "td", N_("Chad") },
	{ "tf", N_("French Southern Territories") },
	{ "tg", N_("Togo") },
	{ "th", N_("Thailand") },
	{ "tj", N_("Tajikistan") },
	{ "tk", N_("Tokelau") },
	{ "tl", N_("Timor-leste") },
	{ "tm", N_("Turkmenistan") },
	{ "tn", N_("Tunisia") },
	{ "to", N_("Tonga") },
	{ "tr", N_("Turkey") },
	{ "tt", N_("Trinidad and Tobago") },
	{ "tv", N_("Tuvalu") },
	{ "tw", N_("Taiwan") },
	{ "tz", N_("Tanzania") },
	{ "ua", N_("Ukraine") },
	{ "ug", N_("Uganda") },
	{ "um", N_("United States Minor Outlying Islands") },
	{ "us", N_("United States") },
	{ "uy", N_("Uruguay") },
	{ "uz", N_("Uzbekistan") },
	{ "va", N_("Holy See (Vatican City State)") },
	{ "vc", N_("Saint Vincent and The Grenadines") },
	{ "ve", N_("Venezuela") },
	{ "vg", N_("British Virgin Islands") },
	{ "vi", N_("U.S. Virgin Islands") },
	{ "vn", N_("Viet Nam") },
	{ "vu", N_("Vanuatu") },
	{ "wf", N_("Wallis and Futuna") },
	{ "ws", N_("Samoa") },
	{ "ye", N_("Yemen") },
	{ "yt", N_("Mayotte") },
	{ "za", N_("South Africa") },
	{ "zm", N_("Zambia") },
	{ "zw", N_("Zimbabwe") },

	/* Above line intentionally left blank for vi sorting */
};

static iso3166_entry_t iso3166_entries[G_N_ELEMENTS(iso3166_tab)];

static iso3166_entry_t *iso3166_countries[ISO3166_NUM_CODES];

/**
 * Decodes a valid country code into a 2-letter country string.
 *
 * @return NULL if integer isn't a validly encoded country code. If the country
 *		   is valid, a string pointing two the 2-letter code is returned. The
 *		   string is in a static buffer.
 */
static const char *
iso3166_decode_cc(uint16 code)
{
    static char s[3];
    uint i;

    if (code >= G_N_ELEMENTS(iso3166_countries))
        return NULL;

    if (NULL == iso3166_countries[code])
        return NULL;

    i = code / 36;
    g_assert(i < 36);
    s[0] = i + (i < 10 ? '0' : 'a' - 10);
    i = code % 36;
    s[1] = i + (i < 10 ? '0' : 'a' - 10);

    return s;
}

/**
 * Encodes a valid 2-letter country code into an integer.
 *
 * @return ISO3166_INVALID if the given string is obviously not
 *         a 2-letter country code.
 */
uint16
iso3166_encode_cc(const char *cc)
{
    g_assert(cc != NULL);

    if (is_ascii_alnum(cc[0]) && is_ascii_alnum(cc[1]) && '\0' == cc[2]) {
        const char *d;
		uint16 code;
		int error;

		code = parse_uint16(cc, NULL, 36, &error);

		if (code >= G_N_ELEMENTS(iso3166_countries))
			return ISO3166_INVALID;

		g_assert(0 == error);

		if (NULL != iso3166_countries[code]) {
        	d = iso3166_decode_cc(code);
        	g_assert(0 == ascii_strcasecmp(cc, d));
			return code;
		}
    }
    return ISO3166_INVALID;
}

G_GNUC_COLD void
iso3166_init(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(iso3166_tab); i++) {
		iso3166_entry_t *entry;

		entry = &iso3166_entries[i];
		strncpy(entry->cc, iso3166_tab[i].cc, sizeof entry->cc);
		entry->country = atom_str_get(_(iso3166_tab[i].country));

		{
			const char *endptr;
			uint16 code;
			int error;

			code = parse_uint16(entry->cc, &endptr, 36, &error);
			g_assert(*endptr == '\0');
			g_assert(!error);
			g_assert((size_t) code < G_N_ELEMENTS(iso3166_countries));
			iso3166_countries[code] = entry;
		}
	}
}

G_GNUC_COLD void
iso3166_close(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(iso3166_entries); i++) {
		iso3166_entry_t *entry = &iso3166_entries[i];
		atom_str_free_null(&entry->country);
	}
}

static inline const iso3166_entry_t *
iso3166_country_entry(uint16 code)
{
	if (ISO3166_INVALID == code) {
		static const iso3166_entry_t unknown = { "??", "??" };
		return &unknown;
	} else {
		static const iso3166_entry_t none = { "(null)", "??" };
		g_assert(code < G_N_ELEMENTS(iso3166_countries));
		return iso3166_countries[code] ? iso3166_countries[code] : &none;
	}
}

/**
 * Maps a valid encoded country code to the country name.
 *
 * @return NULL integer isn't a validly encoded country code. If the country
 *		   is valid, a string pointing two the country name is returned. Each
 *		   string has its own buffer which is only free()d by iso3166_close().
 */
const char *
iso3166_country_name(uint16 code)
{
	return iso3166_country_entry(code)->country;
}

/**
 * Maps a valid encoded country code to the 2-letter code.
 *
 * @return NULL integer isn't a validly encoded country code. If the country
 *		   is valid, a string pointing two the 2-letter code is returned. Each
 *		   string has its own buffer which is only free()d by iso3166_close().
 */
const char *
iso3166_country_cc(uint16 code)
{
	return iso3166_country_entry(code)->cc;
}

/* vi: set ts=4 sw=4 cindent: */
