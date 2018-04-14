/*
 * Copyright (c) 1996, Robert G. Burger
 * Copyright (c) 2011, Raphael Manfredi
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

/*
 * Copyright (c) 1996 Robert G. Burger. Permission is hereby granted,
 * free of charge, to any person obtaining a copy of this software, to deal
 * in the software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the software.
 *
 * The software is provided "as is," without warranty of any kind, express or
 * implied, including but not limited to the warranties of merchantability,
 * fitness for a particular purpose and noninfringement. In no event shall
 * the author be liable for any claim, damages or other liability, whether
 * in an action of contract, tort or otherwise, arising from, out of or in
 * connection with the software or the use or other dealings in the software.
 *
 * Inclusion in gtk-gnutella done by Raphael Manfredi.
 */

#include "common.h"

#include "float.h"
#include "progname.h"

/* locally defined functions */
static void read_floats(FILE *f);
static int longin(FILE *f);
static double build_float(int s, int e, int high, int low);
extern double ldexp(double d, int e);
static int convert (char *s, char *buf, int prec);

#define bytein(f) fgetc(f)

#define fasl_pair             0
#define fasl_symbol           2
#define fasl_flonum           8
#define fasl_immediate       12

static double *floats;
static int nfloats;

static void read_floats(FILE *f) {
  int n;
  double *fp;

  if ((bytein(f) != '#') || (bytein(f) != '@')
      || (bytein(f) != fasl_symbol) || (longin(f) != 4)
      || (bytein(f) != '5') || (bytein(f) != '.') || (bytein(f) != '0')
      || (bytein(f) != 'g') || (bytein(f) != fasl_pair)) {
    fprintf(stderr, "bad fasl file\n");
    exit(2);
  }

  nfloats = longin(f);
  floats = (double *) malloc(nfloats * sizeof(double));
  for (n = nfloats, fp = floats; n > 0; n--) {
    char s;
    int e, h, l;

    if (bytein(f) != fasl_flonum) {
      fprintf(stderr, "non-flonum in list\n");
      exit(3);
    }
    s = bytein(f);
    e = longin(f);
    h = longin(f);
    l = longin(f);
    *fp++ = build_float(s, e, h, l);
  }

  if ((bytein(f) != fasl_immediate) || (longin(f) != 38)
      || (bytein(f) != EOF)) {
    fprintf(stderr, "improper list\n");
    exit(4);
  }
}

static int longin(FILE *f) {
    int x1, x2, x3, x4;
    x4 = bytein(f);
    x3 = bytein(f);
    x2 = bytein(f);
    x1 = bytein(f);
    return ((x1 << 8 | x2) << 8 | x3) << 8 | x4;
}

static double build_float(int s, int e, int high, int low) {
  double d;

  d = ldexp(high * float_radix + low, e);
  return s ? -d : d;
}

#define IERROR(x) fprintf(stderr, "Unexpected %c in state %d", c, (x)), exit(1)

static int convert(char *s, char *buf, int prec) {
   char c;
   int count, shift, e, eneg;

   count = prec;
   shift = 0;
   e = 0;
   eneg = 0;

 state0:
   c = *s++;
   if (c == 0) goto done;
   else if (c == '0')
      goto state0;
   else if (c == '.') {
      shift--;
      goto state1;
   }
   else if ('0' < c && c <= '9') {
      *buf++ = c;
      count--;
      goto state2;
   }
   else IERROR(0);

 state1: /* Seen 0*.0* */
   c = *s++;
   if (c == 0) goto done;
   else if (c == '0') {
      shift--;
      goto state1;
   }
   else if ('0' < c && c <= '9') {
      *buf++ = c;
      count--;
      goto state3;
   }
   else IERROR(1);

 state2: /* Seen 0*[1-9][0-9]* */
   c = *s++;
   if (c == 0) goto done;
   else if (c == '.') goto state3;
   else if (c == 'e') goto state4;
   else if ('0' <= c && c <= '9') {
      shift++;
      *buf++ = c;
      count--;
      goto state2;
   }
   else IERROR(2);

 state3: /* Seen 0*.0*[1-9][0-9]* */
   c = *s++;
   if (c == 0) goto done;
   else if (c == 'e') goto state4;
   else if ('0' <= c && c <= '9') {
      *buf++ = c;
      count--;
      goto state3;
   }
   else IERROR(3);

 state4: /* Seen number followed by e */
   c = *s++;
   if (c == '+') c = *s++;
   else if (c == '-') c = *s++, eneg = 1;
   while ('0' <= c && c <= '9') {
      e = e*10 + (c - '0');
      c = *s++;
   }
   if (c == 0) goto done;
   else IERROR(4);

 done:
   for (; count > 0; count--) *buf++ = '0';
   *buf = 0;
   return (eneg ? -e : e) + shift;
}

#define USAGE_ERROR (fprintf(stderr, \
	"Usage: %s file base|sprintf|printf|dragon|fixed|compare\n", \
	argv[0]), exit(-1))

int main (int argc, char **argv) {
  FILE *f;

  progstart(argc, argv);

  if (argc != 3) USAGE_ERROR;

  if ((f = fopen(argv[1], "rb")) == NULL) {
    fprintf(stderr, "couldn't open %s\n", argv[1]);
    exit(1);
  }
  read_floats(f);
  fclose(f);
  float_init();		/* Always run this to establish baseline */

  if (strcmp(argv[2], "base") == 0) {
    exit(0);
  }
  else if (strcmp(argv[2], "sprintf") == 0) {
    int n;
    double *fp;
    char s[32];

    for (n = nfloats, fp = floats; n > 0; n--) {
       sprintf(s,"%.17g", *fp++);
    }
  }
  else if (strcmp(argv[2], "printf") == 0) {
    int n;
    double *fp;
    for (n = nfloats, fp = floats; n > 0; n--)
      printf("%.17g\n", *fp++);
  }
  else if (strcmp(argv[2], "dragon") == 0) {
    int n, k;
    double *fp;
    char s[32];

    for (n = nfloats, fp = floats; n > 0; n--) {
      float_dragon(ARYLEN(s), *fp++, &k);
      printf("%s %d\n", s, k);
    }
  }
  else if (strcmp(argv[2], "fixed") == 0) {
    int n, k;
    double *fp;
    char s[32];

    for (n = nfloats, fp = floats; n > 0; n--) {
      float_fixed(ARYLEN(s), *fp++, 17, &k);
      printf(".%se%d\n", s, k+1);
    }
  }
  else if (strcmp(argv[2], "compare") == 0) {
    int n, k1, k2;
    double *fp;
    char s[32], buf[32];

    for (n = nfloats, fp = floats; n > 0; n--, fp++) {
       sprintf(s,"%.17g", *fp);
       k1 = convert(s, buf, 17);
       float_fixed(ARYLEN(s), *fp, 17, &k2);
       if (s[17] == '5') {
         int i;
         char *p, c;
         s[17] = 0;
         if (k1 == k2 && strcmp(s, buf) == 0) continue;
         for (i = 17, p = &s[16]; i > 0; i--) {
           c = *p;
           if (c != '9') {
             *p = c+1;
             break;
           }
           *p-- = '0';
         }
         if (i == 0) {
           *++p = '1';
           k2++;
         }
       }
       if (k1 != k2 || strcmp(s, buf) != 0) {
         printf(".%se%d .%se%d\n", buf, k1+1, s, k2+1);
       }
    }
  }
  else
    USAGE_ERROR;

  return 0;
}

/* vi: set ts=4 sw=4 cindent: */
