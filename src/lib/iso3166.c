/*
 * $Id$
 *
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
 * @file
 *
 * Support for mapping ISO 3166 2-letter codes and country names.
 */

#include "common.h"

RCSID("$Id$");

#include "iso3166.h"
#include "misc.h"
#include "override.h"       /* Must be the last header included */

typedef struct {
	gchar cc[3];
	gchar country[1 /* Adjusted as necessary*/];
} iso3166_entry_t;

/*
 * Suggestion for translators: Translate only the name the of country in
 * which the language is spoken - if the native name is different.
 */

static const struct {
	const char cc[3];
	const char *country;
} iso3166_tab[] = {
	{ "a1", N_("Anonymizing proxies") }, /* Not ISO 3166 */
	{ "a2", N_("Satellite providers") }, /* Not ISO 3166 */
	{ "af", N_("Afghanistan") },
	{ "al", N_("Albania, People's Socialist Republic of") },
	{ "dz", N_("Algeria, People's Democratic Republic of") },
	{ "as", N_("American Samoa") },
	{ "ad", N_("Andorra, Principality of") },
	{ "ao", N_("Angola, Republic of") },
	{ "ai", N_("Anguilla") },
	{ "aq", N_("Antarctica (the territory South of 60 deg S)") },
	{ "ag", N_("Antigua and Barbuda") },
	{ "ar", N_("Argentina, Argentine Republic") },
	{ "am", N_("Armenia") },
	{ "aw", N_("Aruba") },
	{ "ap", N_("Asia/Pacific Region") }, /* Not ISO 3166 */
	{ "au", N_("Australia, Commonwealth of") },
	{ "at", N_("Austria, Republic of") },
	{ "az", N_("Azerbaijan, Republic of") },
	{ "bs", N_("Bahamas, Commonwealth of the") },
	{ "bh", N_("Bahrain, Kingdom of") },
	{ "bd", N_("Bangladesh, People's Republic of") },
	{ "bb", N_("Barbados") },
	{ "by", N_("Belarus") },
	{ "be", N_("Belgium, Kingdom of") },
	{ "bz", N_("Belize") },
	{ "bj", N_("Benin, People's Republic of") },
	{ "bm", N_("Bermuda") },
	{ "bt", N_("Bhutan, Kingdom of") },
	{ "bo", N_("Bolivia, Republic of") },
	{ "ba", N_("Bosnia and Herzegovina") },
	{ "bw", N_("Botswana, Republic of") },
	{ "bv", N_("Bouvet Island (Bouvetoya)") },
	{ "br", N_("Brazil, Federative Republic of") },
	{ "io", N_("British Indian Ocean Territory (Chagos Archipelago)") },
	{ "vg", N_("British Virgin Islands") },
	{ "bn", N_("Brunei Darussalam") },
	{ "bg", N_("Bulgaria, People's Republic of") },
	{ "bf", N_("Burkina Faso") },
	{ "bi", N_("Burundi, Republic of") },
	{ "kh", N_("Cambodia, Kingdom of") },
	{ "cm", N_("Cameroon, United Republic of") },
	{ "ca", N_("Canada") },
	{ "cv", N_("Cape Verde, Republic of") },
	{ "ky", N_("Cayman Islands") },
	{ "cf", N_("Central African Republic") },
	{ "td", N_("Chad, Republic of") },
	{ "cl", N_("Chile, Republic of") },
	{ "cn", N_("China, People's Republic of") },
	{ "cx", N_("Christmas Island") },
	{ "cc", N_("Cocos (Keeling) Islands") },
	{ "co", N_("Colombia, Republic of") },
	{ "km", N_("Comoros, Union of the") },
	{ "cd", N_("Congo, Democratic Republic of") },
	{ "cg", N_("Congo, People's Republic of") },
	{ "ck", N_("Cook Islands") },
	{ "cr", N_("Costa Rica, Republic of") },
	{ "ci", N_("Cote D'Ivoire, Ivory Coast, Republic of the") },
	{ "cu", N_("Cuba, Republic of") },
	{ "cy", N_("Cyprus, Republic of") },
	{ "cz", N_("Czech Republic") },
	{ "dk", N_("Denmark, Kingdom of") },
	{ "dj", N_("Djibouti, Republic of") },
	{ "dm", N_("Dominica, Commonwealth of") },
	{ "do", N_("Dominican Republic") },
	{ "ec", N_("Ecuador, Republic of") },
	{ "eg", N_("Egypt, Arab Republic of") },
	{ "sv", N_("El Salvador, Republic of") },
	{ "gq", N_("Equatorial Guinea, Republic of") },
	{ "er", N_("Eritrea") },
	{ "ee", N_("Estonia") },
	{ "et", N_("Ethiopia") },
	{ "eu", N_("Europe") }, /* Not ISO 3166 */
	{ "fo", N_("Faeroe Islands") },
	{ "fk", N_("Falkland Islands (Malvinas)") },
	{ "fj", N_("Fiji, Republic of the Fiji Islands") },
	{ "fi", N_("Finland, Republic of") },
	{ "fr", N_("France, French Republic") },
	{ "gf", N_("French Guiana") },
	{ "pf", N_("French Polynesia") },
	{ "tf", N_("French Southern Territories") },
	{ "ga", N_("Gabon, Gabonese Republic") },
	{ "gm", N_("Gambia, Republic of the") },
	{ "ge", N_("Georgia") },
	{ "de", N_("Germany") },
	{ "gh", N_("Ghana, Republic of") },
	{ "gi", N_("Gibraltar") },
	{ "gr", N_("Greece, Hellenic Republic") },
	{ "gl", N_("Greenland") },
	{ "gd", N_("Grenada") },
	{ "gp", N_("Guadaloupe") },
	{ "gu", N_("Guam") },
	{ "gt", N_("Guatemala, Republic of") },
	{ "gn", N_("Guinea, Revolutionary People's Rep'c of") },
	{ "gw", N_("Guinea-Bissau, Republic of") },
	{ "gy", N_("Guyana, Republic of") },
	{ "ht", N_("Haiti, Republic of") },
	{ "hm", N_("Heard and McDonald Islands") },
	{ "va", N_("Holy See (Vatican City State)") },
	{ "hn", N_("Honduras, Republic of") },
	{ "hk", N_("Hong Kong, Special Administrative Region of China") },
	{ "hr", N_("Hrvatska (Croatia)") },
	{ "hu", N_("Hungary, Hungarian People's Republic") },
	{ "is", N_("Iceland, Republic of") },
	{ "in", N_("India, Republic of") },
	{ "id", N_("Indonesia, Republic of") },
	{ "ir", N_("Iran, Islamic Republic of") },
	{ "iq", N_("Iraq, Republic of") },
	{ "ie", N_("Ireland") },
	{ "il", N_("Israel, State of") },
	{ "it", N_("Italy, Italian Republic") },
	{ "jm", N_("Jamaica") },
	{ "jp", N_("Japan") },
	{ "jo", N_("Jordan, Hashemite Kingdom of") },
	{ "kz", N_("Kazakhstan, Republic of") },
	{ "ke", N_("Kenya, Republic of") },
	{ "ki", N_("Kiribati, Republic of") },
	{ "kp", N_("Korea, Democratic People's Republic of") },
	{ "kr", N_("Korea, Republic of") },
	{ "kw", N_("Kuwait, State of") },
	{ "kg", N_("Kyrgyz Republic") },
	{ "la", N_("Lao People's Democratic Republic") },
	{ "lv", N_("Latvia") },
	{ "lb", N_("Lebanon, Lebanese Republic") },
	{ "ls", N_("Lesotho, Kingdom of") },
	{ "lr", N_("Liberia, Republic of") },
	{ "ly", N_("Libyan Arab Jamahiriya") },
	{ "li", N_("Liechtenstein, Principality of") },
	{ "lt", N_("Lithuania") },
	{ "lu", N_("Luxembourg, Grand Duchy of") },
	{ "mo", N_("Macao, Special Administrative Region of China") },
	{ "mk", N_("Macedonia, the former Yugoslav Republic of") },
	{ "mg", N_("Madagascar, Republic of") },
	{ "mw", N_("Malawi, Republic of") },
	{ "my", N_("Malaysia") },
	{ "mv", N_("Maldives, Republic of") },
	{ "ml", N_("Mali, Republic of") },
	{ "mt", N_("Malta, Republic of") },
	{ "mh", N_("Marshall Islands") },
	{ "mq", N_("Martinique") },
	{ "mr", N_("Mauritania, Islamic Republic of") },
	{ "mu", N_("Mauritius") },
	{ "yt", N_("Mayotte") },
	{ "mx", N_("Mexico, United Mexican States") },
	{ "fm", N_("Micronesia, Federated States of") },
	{ "md", N_("Moldova, Republic of") },
	{ "mc", N_("Monaco, Principality of") },
	{ "mn", N_("Mongolia, Mongolian People's Republic") },
	{ "ms", N_("Montserrat") },
	{ "ma", N_("Morocco, Kingdom of") },
	{ "mz", N_("Mozambique, People's Republic of") },
	{ "mm", N_("Myanmar") },
	{ "na", N_("Namibia") },
	{ "nr", N_("Nauru, Republic of") },
	{ "np", N_("Nepal, Kingdom of") },
	{ "an", N_("Netherlands Antilles") },
	{ "nl", N_("Netherlands, Kingdom of the") },
	{ "nc", N_("New Caledonia") },
	{ "nz", N_("New Zealand") },
	{ "ni", N_("Nicaragua, Republic of") },
	{ "ne", N_("Niger, Republic of the") },
	{ "ng", N_("Nigeria, Federal Republic of") },
	{ "nu", N_("Niue, Republic of") },
	{ "nf", N_("Norfolk Island") },
	{ "mp", N_("Northern Mariana Islands") },
	{ "no", N_("Norway, Kingdom of") },
	{ "om", N_("Oman, Sultanate of") },
	{ "pk", N_("Pakistan, Islamic Republic of") },
	{ "pw", N_("Palau") },
	{ "ps", N_("Palestinian Territory, Occupied") },
	{ "pa", N_("Panama, Republic of") },
	{ "pg", N_("Papua New Guinea") },
	{ "py", N_("Paraguay, Republic of") },
	{ "pe", N_("Peru, Republic of") },
	{ "ph", N_("Philippines, Republic of the") },
	{ "pn", N_("Pitcairn Island") },
	{ "pl", N_("Poland, Polish People's Republic") },
	{ "pt", N_("Portugal, Portuguese Republic") },
	{ "pr", N_("Puerto Rico") },
	{ "qa", N_("Qatar, State of") },
	{ "re", N_("Reunion") },
	{ "ro", N_("Romania, Socialist Republic of") },
	{ "ru", N_("Russian Federation") },
	{ "rw", N_("Rwanda, Rwandese Republic") },
	{ "sh", N_("St. Helena") },
	{ "kn", N_("St. Kitts and Nevis") },
	{ "lc", N_("St. Lucia") },
	{ "pm", N_("St. Pierre and Miquelon") },
	{ "vc", N_("St. Vincent and the Grenadines") },
	{ "ws", N_("Samoa, Independent State of") },
	{ "sm", N_("San Marino, Republic of") },
	{ "st", N_("Sao Tome and Principe, Democratic Republic of") },
	{ "sa", N_("Saudi Arabia, Kingdom of") },
	{ "sn", N_("Senegal, Republic of") },
	{ "cs", N_("Serbia and Montenegro") },
	{ "sc", N_("Seychelles, Republic of") },
	{ "sl", N_("Sierra Leone, Republic of") },
	{ "sg", N_("Singapore, Republic of") },
	{ "sk", N_("Slovakia (Slovak Republic)") },
	{ "si", N_("Slovenia") },
	{ "sb", N_("Solomon Islands") },
	{ "so", N_("Somalia, Somali Republic") },
	{ "za", N_("South Africa, Republic of") },
	{ "gs", N_("South Georgia and the South Sandwich Islands") },
	{ "es", N_("Spain, Spanish State") },
	{ "lk", N_("Sri Lanka, Democratic Socialist Republic of") },
	{ "sd", N_("Sudan, Democratic Republic of the") },
	{ "sr", N_("Suriname, Republic of") },
	{ "sj", N_("Svalbard & Jan Mayen Islands") },
	{ "sz", N_("Swaziland, Kingdom of") },
	{ "se", N_("Sweden, Kingdom of") },
	{ "ch", N_("Switzerland, Swiss Confederation") },
	{ "sy", N_("Syrian Arab Republic") },
	{ "tw", N_("Taiwan, Province of China") },
	{ "tj", N_("Tajikistan") },
	{ "tz", N_("Tanzania, United Republic of") },
	{ "th", N_("Thailand, Kingdom of") },
	{ "tl", N_("Timor-Leste, Democratic Republic of") },
	{ "tg", N_("Togo, Togolese Republic") },
	{ "tk", N_("Tokelau (Tokelau Islands)") },
	{ "to", N_("Tonga, Kingdom of") },
	{ "tt", N_("Trinidad and Tobago, Republic of") },
	{ "tn", N_("Tunisia, Republic of") },
	{ "tr", N_("Turkey, Republic of") },
	{ "tm", N_("Turkmenistan") },
	{ "tc", N_("Turks and Caicos Islands") },
	{ "tv", N_("Tuvalu") },
	{ "vi", N_("US Virgin Islands") },
	{ "ug", N_("Uganda, Republic of") },
	{ "ua", N_("Ukraine") },
	{ "ae", N_("United Arab Emirates") },
	{ "gb", N_("United Kingdom of Great Britain & N. Ireland") },
	{ "um", N_("United States Minor Outlying Islands") },
	{ "us", N_("United States of America") },
	{ "uy", N_("Uruguay, Eastern Republic of") },
	{ "uz", N_("Uzbekistan") },
	{ "vu", N_("Vanuatu") },
	{ "ve", N_("Venezuela, Bolivarian Republic of") },
	{ "vn", N_("Viet Nam, Socialist Republic of") },
	{ "wf", N_("Wallis and Futuna Islands") },
	{ "eh", N_("Western Sahara") },
	{ "ye", N_("Yemen") },
	{ "yu", N_("Yugoslavia") },	/* Not ISO 3166 any longer (historical) */
	{ "zm", N_("Zambia, Republic of") },
	{ "zw", N_("Zimbabwe") }
};

#define NUM_CODES (36 * 35 + 35)
static iso3166_entry_t *iso3166_countries[NUM_CODES];

/**
 * Decodes a valid 2-letter country code into an integer.
 * @return NULL integer isn't a validly encoded country code. If the country
 *		   is valid, a string pointing two the 2-letter code is returned. The
 *		   string is in a static buffer.
 */
static const gchar *
iso3166_decode_cc(gint code)
{
    static gchar s[3];
    gint i;

    if (code < 0 || (size_t) code >= G_N_ELEMENTS(iso3166_countries))
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
 * @return -1 if the given string is obviously not a 2-letter country code.
 */
gint
iso3166_encode_cc(const gchar *cc)
{
    g_assert(cc != NULL);

    if (is_ascii_alnum(cc[0]) && is_ascii_alnum(cc[1]) && '\0' == cc[2]) {
        const gchar *d;
		guint64 v;
		int error;

		v = parse_uint64(cc, NULL, 36, &error);
        g_assert(v < G_N_ELEMENTS(iso3166_countries));
        g_assert(0 == error);

		if (NULL != iso3166_countries[v]) {
			gint code = v;
        	d = iso3166_decode_cc(code);
        	g_assert(0 == ascii_strcasecmp(cc, d));
			return code;
		}
    }
    return -1;
}


void
iso3166_init(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(iso3166_tab); i++) {
		const gchar *country, *cc;
		iso3166_entry_t *e;
		size_t size;
		gint code, error;
		gchar *ep;

		country = _(iso3166_tab[i].country);
		cc = iso3166_tab[i].cc;
		size = strlen(country) + 1;
		e = g_malloc(size + sizeof *e);
		strncpy(e->cc, cc, sizeof e->cc);
		memcpy(e->country, country, size);

		code = parse_uint64(cc, &ep, 36, &error);
		g_assert(*ep == '\0');
		g_assert(!error);
		g_assert(code >= 0 && (size_t) code < G_N_ELEMENTS(iso3166_countries));
		iso3166_countries[code] = e;
	}
}

void
iso3166_close(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(iso3166_countries); i++) {
		if (iso3166_countries[i])
			G_FREE_NULL(iso3166_countries[i]);
	}
}

/**
 * Maps a valid encoded country code to the country name.
 *
 * @return NULL integer isn't a validly encoded country code. If the country
 *		   is valid, a string pointing two the country name is returned. Each
 *		   string has its own buffer which is only free()d by iso3166_close().
 */
const gchar *
iso3166_country_name(gint code)
{
	iso3166_entry_t *e;
	
	g_assert(code >= -1 && code < (gint) G_N_ELEMENTS(iso3166_countries));
	if (-1 == code)
		return "??";
	
	e = iso3166_countries[code];
	return e ? e->country : "(null)";
}

/**
 * Maps a valid encoded country code to the 2-letter code.
 *
 * @return NULL integer isn't a validly encoded country code. If the country
 *		   is valid, a string pointing two the 2-letter code is returned. Each
 *		   string has its own buffer which is only free()d by iso3166_close().
 */
const gchar *
iso3166_country_cc(gint code)
{
	iso3166_entry_t *e;
	
	g_assert(code >= -1 && code < (gint) G_N_ELEMENTS(iso3166_countries));
	if (-1 == code)
		return "??";
	
	e = iso3166_countries[code];
	return e ? e->cc : "(null)";
}

/* vi: set ts=4 sw=4 cindent: */
