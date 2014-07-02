#if 0
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#include <stdlib.h>
#include <string.h>

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20090221

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
#ifdef YYPARSE_PARAM_TYPE
#define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
#else
#define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
#endif
#else
#define YYPARSE_DECL() yyparse(void)
#endif /* YYPARSE_PARAM */

extern int YYPARSE_DECL();

static int yygrowstack(void);
#define YYPREFIX "yy"
#line 2 "getdate.y"
/*
 * Date parsing.
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
**  Originally written by Steven M. Bellovin <smb@research.att.com> while
**  at the University of North Carolina at Chapel Hill.  Later tweaked by
**  a couple of people on Usenet.  Completely overhauled by Rich $alz
**  <rsalz@bbn.com> and Jim Berets <jberets@bbn.com> in August, 1990;
**
**  Modified by Raphael Manfredi <Rapahel_Manfredi@pobox.com> to add
**  support for Gnutella's ISO date format (see NOTE-datetime.txt in
**  the gtk-gnutella's doc/other directory) in May, 2002.
**
**  This grammar has 14 shift/reduce conflicts.
**
**  This code is in the public domain and has no copyright.
*/

#include "common.h"

#ifdef FORCE_ALLOCA_H
#include <alloca.h>
#endif

/* Since the code of getdate.y is not included in the Emacs executable
 * itself, there is no need to #define static in this file.  Even if
 * the code were included in the Emacs executable, it probably
 * wouldn't do any harm to #undef it here; this will only cause
 * problems if we try to write to a static variable, which I don't
 * think this code needs to do.
 */

#ifdef emacs
# undef static
#endif

#if defined (STDC_HEADERS) || (!defined (isascii) && !defined (HAS_ISASCII))
# define IN_CTYPE_DOMAIN(c) 1
#else
# define IN_CTYPE_DOMAIN(c) isascii(c)
#endif

#define ISSPACE(c) (IN_CTYPE_DOMAIN (c) && isspace (c))
#define ISALPHA(c) (IN_CTYPE_DOMAIN (c) && isalpha (c))
#define ISUPPER(c) (IN_CTYPE_DOMAIN (c) && isupper (c))
#define ISDIGIT_LOCALE(c) (IN_CTYPE_DOMAIN (c) && isdigit (c))

/* ISDIGIT differs from ISDIGIT_LOCALE, as follows:
   - Its arg may be any int or unsigned int; it need not be an unsigned char.
   - It's guaranteed to evaluate its argument exactly once.
   - It's typically faster.
   Posix 1003.2-1992 section 2.5.2.1 page 50 lines 1556-1558 says that
   only '0' through '9' are digits.  Prefer ISDIGIT to ISDIGIT_LOCALE unless
   it's important to use the locale's definition of `digit' even when the
   host does not conform to Posix.  */
#define ISDIGIT(c) ((unsigned) (c) - '0' <= 9)

#include "getdate.h"
#include "offtime.h"		/* For TM_YEAR_ORIGIN */
#include "timestamp.h"		/* For diff_tm */

/* Some old versions of bison generate parsers that use bcopy.
   That loses on systems that don't provide the function, so we have
   to redefine it here.  */
#if !defined (HAS_BCOPY) && defined (HAS_MEMCPY) && !defined (bcopy)
# define bcopy(from, to, len) memcpy ((to), (from), (len))
#endif

/*
 * Remap normal yacc parser interface names (yyparse, yylex, yyerror, etc),
 * as well as gratuitiously global symbol names, so we can have multiple
 * yacc generated parsers in the same program.  Note that these are only
 * the variables produced by yacc.  If other parser generators (bison,
 * byacc, etc) produce additional global names that conflict at link time,
 * then those parser generators need to be fixed instead of adding those
 * names to this list.
 */

#define yymaxdepth gd_maxdepth
#define yyparse gd_parse
#define yylex   gd_lex
#define yyerror gd_error
#define yylval  gd_lval
#define yychar  gd_char
#define yydebug gd_debug
#define yypact  gd_pact
#define yyr1    gd_r1
#define yyr2    gd_r2
#define yydef   gd_def
#define yychk   gd_chk
#define yypgo   gd_pgo
#define yyact   gd_act
#define yyexca  gd_exca
#define yyerrflag gd_errflag
#define yynerrs gd_nerrs
#define yyps    gd_ps
#define yypv    gd_pv
#define yys     gd_s
#define yy_yys  gd_yys
#define yystate gd_state
#define yytmp   gd_tmp
#define yyv     gd_v
#define yy_yyv  gd_yyv
#define yyval   gd_val
#define yylloc  gd_lloc
#define yyreds  gd_reds          /* With YYDEBUG defined */
#define yytoks  gd_toks          /* With YYDEBUG defined */
#define yylhs   gd_yylhs
#define yylen   gd_yylen
#define yydefred gd_yydefred
#define yydgoto gd_yydgoto
#define yysindex gd_yysindex
#define yyrindex gd_yyrindex
#define yygindex gd_yygindex
#define yytable  gd_yytable
#define yycheck  gd_yycheck

static int yylex (void);
static int yyerror (const char *s);
extern int yyparse (void);

#define EPOCH		1970
#define HOUR(x)		((x) * 60)

#define MAX_BUFF_LEN    128   /* size of buffer to read the date into */

/*
**  An entry in the lexical lookup table.
*/
typedef struct _TABLE {
    const char	*name;
    int		type;
    int		value;
} TABLE;


/*
**  Meridian:  am, pm, or 24-hour style.
*/
typedef enum _MERIDIAN {
    MERam, MERpm, MER24
} MERIDIAN;


/*
**  Global variables.  We could get rid of most of these by using a good
**  union as the yacc stack.  (This routine was originally written before
**  yacc had the %union construct.)  Maybe someday; right now we only use
**  the %union very rarely.
*/
static const unsigned char	*yyInput;
static int	yyDayOrdinal;
static int	yyDayNumber;
static int	yyHaveDate;
static int	yyHaveDay;
static int	yyHaveRel;
static int	yyHaveTime;
static int	yyHaveZone;
static int	yyTimezone;
static int	yyDay;
static int	yyHour;
static int	yyMinutes;
static int	yyMonth;
static int	yySeconds;
static int	yyYear;
static MERIDIAN	yyMeridian;
static int	yyRelDay;
static int	yyRelHour;
static int	yyRelMinutes;
static int	yyRelMonth;
static int	yyRelSeconds;
static int	yyRelYear;

#line 198 "getdate.y"
typedef union {
    int			Number;
    enum _MERIDIAN	Meridian;
} YYSTYPE;
#line 234 "y.tab.c"
#define tAGO 257
#define tDAY 258
#define tDAY_UNIT 259
#define tDAYZONE 260
#define tDST 261
#define tHOUR_UNIT 262
#define tID 263
#define tMERIDIAN 264
#define tMINUTE_UNIT 265
#define tMONTH 266
#define tMONTH_UNIT 267
#define tSEC_UNIT 268
#define tSNUMBER 269
#define tUNUMBER 270
#define tYEAR_UNIT 271
#define tZONE 272
#define tNUMBER_T 273
#define tNUMBER_DOT 274
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    0,    0,    2,    2,    2,    2,    2,    2,    3,    3,
    3,    3,    3,    3,    3,    3,    4,    4,    4,    9,
    6,    6,    6,    5,    5,    5,    5,    5,    5,    5,
    5,    5,    7,    7,   10,   10,   10,   10,   10,   10,
   10,   10,   10,   10,   10,   10,   10,   10,   10,   10,
   10,   10,    8,    1,    1,
};
static const short yylen[] = {                            2,
    0,    2,    1,    1,    1,    1,    1,    1,    2,    4,
    4,    6,    6,    6,    7,    6,    1,    1,    2,    3,
    1,    2,    2,    3,    5,    3,    3,    3,    2,    4,
    2,    3,    2,    1,    2,    2,    1,    2,    2,    1,
    2,    2,    1,    2,    2,    1,    2,    2,    1,    2,
    2,    1,    1,    0,    1,
};
static const short yydefred[] = {                         1,
    0,    0,   43,   18,   46,   49,    0,   40,   52,    0,
    0,   37,    0,    2,    3,    4,    5,    6,    7,    8,
    0,   22,    0,   42,   45,   48,   39,   51,   36,   23,
   41,   44,    9,   47,    0,   38,   50,    0,   35,    0,
    0,   19,   33,    0,   28,   32,   26,   27,    0,    0,
   30,   55,   11,    0,   10,    0,    0,    0,   25,    0,
   12,   13,    0,    0,    0,   15,   20,
};
static const short yydgoto[] = {                          1,
   55,   14,   15,   16,   17,   18,   19,   20,   62,   21,
};
static const short yysindex[] = {                         0,
 -245,  -40,    0,    0,    0,    0, -260,    0,    0, -230,
  -47,    0, -249,    0,    0,    0,    0,    0,    0,    0,
 -239,    0,  -25,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -263,    0,    0, -264,    0, -242,
 -237,    0,    0, -234,    0,    0,    0,    0,  -56,   -8,
    0,    0,    0, -240,    0, -228, -261, -227,    0,  -18,
    0,    0, -225, -223,  -18,    0,    0,
};
static const short yyrindex[] = {                         0,
    0,    1,    0,    0,    0,    0,    0,    0,    0,    0,
  124,    0,   16,    0,    0,    0,    0,    0,    0,    0,
   31,    0,   46,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  121,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   91,   61,
    0,    0,    0,    0,    0,    0,   91,    0,    0,   76,
    0,    0,  106,    0,    0,    0,    0,
};
static const short yygindex[] = {                         0,
  -12,    0,    0,    0,    0,    0,    0,    0,  -15,    0,
};
#define YYTABLESIZE 396
static const short yytable[] = {                         41,
   21,   54,   52,   22,   47,   45,   46,   60,   48,   23,
   40,   42,    2,    3,    4,   17,    5,   43,   44,    6,
    7,    8,    9,   10,   11,   12,   13,   49,   24,   57,
   34,   25,   50,   58,   26,   51,   27,   28,   56,   64,
   29,   59,   63,   65,   61,   29,   67,   66,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   24,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   16,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   54,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   14,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   31,    0,    0,   53,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   52,    0,    0,
   30,   31,   53,    0,   32,    0,   33,   34,   35,   36,
   37,   38,    0,   39,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   21,   21,
   21,    0,   21,    0,    0,   21,   21,   21,   21,   21,
   21,   21,   21,   17,   17,   17,    0,   17,    0,    0,
   17,   17,   17,   17,   17,   17,   17,   17,   34,   34,
   34,    0,   34,    0,    0,   34,   34,   34,   34,   34,
   34,   34,   34,   29,   29,   29,    0,   29,    0,    0,
   29,   29,   29,   29,   29,   29,   29,   29,   24,   24,
   24,    0,   24,    0,    0,   24,   24,   24,   24,   24,
   24,   24,   24,   16,   16,   16,    0,   16,    0,    0,
   16,   16,   16,   16,   16,   16,   16,   16,   54,   54,
   54,    0,   54,    0,    0,   54,   54,   54,   54,    0,
   54,   54,   54,   14,   14,   14,    0,   14,    0,    0,
   14,   14,   14,   14,    0,   14,   14,   14,   31,   31,
   31,    0,   31,   53,    0,   31,   31,   31,   31,    0,
    0,   31,   31,   53,    0,   53,
};
static const short yycheck[] = {                         47,
    0,   58,  264,   44,  269,  269,  270,  269,  273,  270,
   58,  261,  258,  259,  260,    0,  262,  257,   44,  265,
  266,  267,  268,  269,  270,  271,  272,  270,  259,  270,
    0,  262,  270,  274,  265,  270,  267,  268,   47,   58,
  271,  270,  270,  269,   57,    0,  270,   63,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,    0,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  264,   -1,   -1,
  258,  259,  269,   -1,  262,   -1,  264,  265,  266,  267,
  268,  269,   -1,  271,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  258,  259,
  260,   -1,  262,   -1,   -1,  265,  266,  267,  268,  269,
  270,  271,  272,  258,  259,  260,   -1,  262,   -1,   -1,
  265,  266,  267,  268,  269,  270,  271,  272,  258,  259,
  260,   -1,  262,   -1,   -1,  265,  266,  267,  268,  269,
  270,  271,  272,  258,  259,  260,   -1,  262,   -1,   -1,
  265,  266,  267,  268,  269,  270,  271,  272,  258,  259,
  260,   -1,  262,   -1,   -1,  265,  266,  267,  268,  269,
  270,  271,  272,  258,  259,  260,   -1,  262,   -1,   -1,
  265,  266,  267,  268,  269,  270,  271,  272,  258,  259,
  260,   -1,  262,   -1,   -1,  265,  266,  267,  268,   -1,
  270,  271,  272,  258,  259,  260,   -1,  262,   -1,   -1,
  265,  266,  267,  268,   -1,  270,  271,  272,  258,  259,
  260,   -1,  262,  260,   -1,  265,  266,  267,  268,   -1,
   -1,  271,  272,  270,   -1,  272,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 274
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,"','",0,0,"'/'",0,0,0,0,0,0,0,0,0,0,"':'",0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"tAGO","tDAY",
"tDAY_UNIT","tDAYZONE","tDST","tHOUR_UNIT","tID","tMERIDIAN","tMINUTE_UNIT",
"tMONTH","tMONTH_UNIT","tSEC_UNIT","tSNUMBER","tUNUMBER","tYEAR_UNIT","tZONE",
"tNUMBER_T","tNUMBER_DOT",
};
static const char *yyrule[] = {
"$accept : spec",
"spec :",
"spec : spec item",
"item : time",
"item : zone",
"item : date",
"item : day",
"item : rel",
"item : number",
"time : tUNUMBER tMERIDIAN",
"time : tUNUMBER ':' tUNUMBER o_merid",
"time : tUNUMBER ':' tUNUMBER tSNUMBER",
"time : tUNUMBER ':' tUNUMBER ':' tUNUMBER o_merid",
"time : tUNUMBER ':' tUNUMBER ':' tUNUMBER isozone",
"time : tUNUMBER ':' tUNUMBER ':' tNUMBER_DOT tUNUMBER",
"time : tUNUMBER ':' tUNUMBER ':' tNUMBER_DOT tUNUMBER isozone",
"time : tUNUMBER ':' tUNUMBER ':' tUNUMBER tSNUMBER",
"zone : tZONE",
"zone : tDAYZONE",
"zone : tZONE tDST",
"isozone : tSNUMBER ':' tUNUMBER",
"day : tDAY",
"day : tDAY ','",
"day : tUNUMBER tDAY",
"date : tUNUMBER '/' tUNUMBER",
"date : tUNUMBER '/' tUNUMBER '/' tUNUMBER",
"date : tUNUMBER tSNUMBER tSNUMBER",
"date : tUNUMBER tSNUMBER tNUMBER_T",
"date : tUNUMBER tMONTH tSNUMBER",
"date : tMONTH tUNUMBER",
"date : tMONTH tUNUMBER ',' tUNUMBER",
"date : tUNUMBER tMONTH",
"date : tUNUMBER tMONTH tUNUMBER",
"rel : relunit tAGO",
"rel : relunit",
"relunit : tUNUMBER tYEAR_UNIT",
"relunit : tSNUMBER tYEAR_UNIT",
"relunit : tYEAR_UNIT",
"relunit : tUNUMBER tMONTH_UNIT",
"relunit : tSNUMBER tMONTH_UNIT",
"relunit : tMONTH_UNIT",
"relunit : tUNUMBER tDAY_UNIT",
"relunit : tSNUMBER tDAY_UNIT",
"relunit : tDAY_UNIT",
"relunit : tUNUMBER tHOUR_UNIT",
"relunit : tSNUMBER tHOUR_UNIT",
"relunit : tHOUR_UNIT",
"relunit : tUNUMBER tMINUTE_UNIT",
"relunit : tSNUMBER tMINUTE_UNIT",
"relunit : tMINUTE_UNIT",
"relunit : tUNUMBER tSEC_UNIT",
"relunit : tSNUMBER tSEC_UNIT",
"relunit : tSEC_UNIT",
"number : tUNUMBER",
"o_merid :",
"o_merid : tMERIDIAN",

};
#endif
#if YYDEBUG
#include <stdio.h>
#endif

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;
int      yyerrflag;
int      yychar;
short   *yyssp;
YYSTYPE *yyvsp;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static short   *yyss;
static short   *yysslim;
static YYSTYPE *yyvs;
static unsigned yystacksize;
#line 502 "getdate.y"

/* Month and day table. */
static TABLE const MonthDayTable[] = {
    { "january",	tMONTH,  1 },
    { "february",	tMONTH,  2 },
    { "march",		tMONTH,  3 },
    { "april",		tMONTH,  4 },
    { "may",		tMONTH,  5 },
    { "june",		tMONTH,  6 },
    { "july",		tMONTH,  7 },
    { "august",		tMONTH,  8 },
    { "september",	tMONTH,  9 },
    { "sept",		tMONTH,  9 },
    { "october",	tMONTH, 10 },
    { "november",	tMONTH, 11 },
    { "december",	tMONTH, 12 },
    { "sunday",		tDAY, 0 },
    { "monday",		tDAY, 1 },
    { "tuesday",	tDAY, 2 },
    { "tues",		tDAY, 2 },
    { "wednesday",	tDAY, 3 },
    { "wednes",		tDAY, 3 },
    { "thursday",	tDAY, 4 },
    { "thur",		tDAY, 4 },
    { "thurs",		tDAY, 4 },
    { "friday",		tDAY, 5 },
    { "saturday",	tDAY, 6 },
    { NULL,		0, 0 }
};

/* Time units table. */
static TABLE const UnitsTable[] = {
    { "year",		tYEAR_UNIT,	1 },
    { "month",		tMONTH_UNIT,	1 },
    { "fortnight",	tDAY_UNIT,	14 },
    { "week",		tDAY_UNIT,	7 },
    { "day",		tDAY_UNIT,	1 },
    { "hour",		tHOUR_UNIT,	1 },
    { "minute",		tMINUTE_UNIT,	1 },
    { "min",		tMINUTE_UNIT,	1 },
    { "second",		tSEC_UNIT,	1 },
    { "sec",		tSEC_UNIT,	1 },
    { NULL,		0,		0 }
};

/* Assorted relative-time words. */
static TABLE const OtherTable[] = {
    { "tomorrow",	tMINUTE_UNIT,	1 * 24 * 60 },
    { "yesterday",	tMINUTE_UNIT,	-1 * 24 * 60 },
    { "today",		tMINUTE_UNIT,	0 },
    { "now",		tMINUTE_UNIT,	0 },
    { "last",		tUNUMBER,	-1 },
    { "this",		tMINUTE_UNIT,	0 },
    { "next",		tUNUMBER,	2 },
    { "first",		tUNUMBER,	1 },
/*  { "second",		tUNUMBER,	2 }, */
    { "third",		tUNUMBER,	3 },
    { "fourth",		tUNUMBER,	4 },
    { "fifth",		tUNUMBER,	5 },
    { "sixth",		tUNUMBER,	6 },
    { "seventh",	tUNUMBER,	7 },
    { "eighth",		tUNUMBER,	8 },
    { "ninth",		tUNUMBER,	9 },
    { "tenth",		tUNUMBER,	10 },
    { "eleventh",	tUNUMBER,	11 },
    { "twelfth",	tUNUMBER,	12 },
    { "ago",		tAGO,	1 },
    { NULL,		0,	0 }
};

/* The timezone table. */
static TABLE const TimezoneTable[] = {
    { "gmt",	tZONE,     HOUR ( 0) },	/* Greenwich Mean */
    { "ut",	tZONE,     HOUR ( 0) },	/* Universal (Coordinated) */
    { "utc",	tZONE,     HOUR ( 0) },
    { "wet",	tZONE,     HOUR ( 0) },	/* Western European */
    { "bst",	tDAYZONE,  HOUR ( 0) },	/* British Summer */
    { "wat",	tZONE,     HOUR ( 1) },	/* West Africa */
    { "at",	tZONE,     HOUR ( 2) },	/* Azores */
#if	0
    /* For completeness.  BST is also British Summer, and GST is
     * also Guam Standard. */
    { "bst",	tZONE,     HOUR ( 3) },	/* Brazil Standard */
    { "gst",	tZONE,     HOUR ( 3) },	/* Greenland Standard */
#endif
#if 0
    { "nft",	tZONE,     HOUR (3.5) },	/* Newfoundland */
    { "nst",	tZONE,     HOUR (3.5) },	/* Newfoundland Standard */
    { "ndt",	tDAYZONE,  HOUR (3.5) },	/* Newfoundland Daylight */
#endif
    { "ast",	tZONE,     HOUR ( 4) },	/* Atlantic Standard */
    { "adt",	tDAYZONE,  HOUR ( 4) },	/* Atlantic Daylight */
    { "est",	tZONE,     HOUR ( 5) },	/* Eastern Standard */
    { "edt",	tDAYZONE,  HOUR ( 5) },	/* Eastern Daylight */
    { "cst",	tZONE,     HOUR ( 6) },	/* Central Standard */
    { "cdt",	tDAYZONE,  HOUR ( 6) },	/* Central Daylight */
    { "mst",	tZONE,     HOUR ( 7) },	/* Mountain Standard */
    { "mdt",	tDAYZONE,  HOUR ( 7) },	/* Mountain Daylight */
    { "pst",	tZONE,     HOUR ( 8) },	/* Pacific Standard */
    { "pdt",	tDAYZONE,  HOUR ( 8) },	/* Pacific Daylight */
    { "yst",	tZONE,     HOUR ( 9) },	/* Yukon Standard */
    { "ydt",	tDAYZONE,  HOUR ( 9) },	/* Yukon Daylight */
    { "hst",	tZONE,     HOUR (10) },	/* Hawaii Standard */
    { "hdt",	tDAYZONE,  HOUR (10) },	/* Hawaii Daylight */
    { "cat",	tZONE,     HOUR (10) },	/* Central Alaska */
    { "ahst",	tZONE,     HOUR (10) },	/* Alaska-Hawaii Standard */
    { "nt",	tZONE,     HOUR (11) },	/* Nome */
    { "idlw",	tZONE,     HOUR (12) },	/* International Date Line West */
    { "cet",	tZONE,     -HOUR (1) },	/* Central European */
    { "met",	tZONE,     -HOUR (1) },	/* Middle European */
    { "mewt",	tZONE,     -HOUR (1) },	/* Middle European Winter */
    { "mest",	tDAYZONE,  -HOUR (1) },	/* Middle European Summer */
    { "mesz",	tDAYZONE,  -HOUR (1) },	/* Middle European Summer */
    { "swt",	tZONE,     -HOUR (1) },	/* Swedish Winter */
    { "sst",	tDAYZONE,  -HOUR (1) },	/* Swedish Summer */
    { "fwt",	tZONE,     -HOUR (1) },	/* French Winter */
    { "fst",	tDAYZONE,  -HOUR (1) },	/* French Summer */
    { "eet",	tZONE,     -HOUR (2) },	/* Eastern Europe, USSR Zone 1 */
    { "bt",	tZONE,     -HOUR (3) },	/* Baghdad, USSR Zone 2 */
#if 0
    { "it",	tZONE,     -HOUR (3.5) },/* Iran */
#endif
    { "zp4",	tZONE,     -HOUR (4) },	/* USSR Zone 3 */
    { "zp5",	tZONE,     -HOUR (5) },	/* USSR Zone 4 */
#if 0
    { "ist",	tZONE,     -HOUR (5.5) },/* Indian Standard */
#endif
    { "zp6",	tZONE,     -HOUR (6) },	/* USSR Zone 5 */
#if	0
    /* For completeness.  NST is also Newfoundland Standard, and SST is
     * also Swedish Summer. */
    { "nst",	tZONE,     -HOUR (6.5) },/* North Sumatra */
    { "sst",	tZONE,     -HOUR (7) },	/* South Sumatra, USSR Zone 6 */
#endif	/* 0 */
    { "wast",	tZONE,     -HOUR (7) },	/* West Australian Standard */
    { "wadt",	tDAYZONE,  -HOUR (7) },	/* West Australian Daylight */
#if 0
    { "jt",	tZONE,     -HOUR (7.5) },/* Java (3pm in Cronusland!) */
#endif
    { "cct",	tZONE,     -HOUR (8) },	/* China Coast, USSR Zone 7 */
    { "jst",	tZONE,     -HOUR (9) },	/* Japan Standard, USSR Zone 8 */
#if 0
    { "cast",	tZONE,     -HOUR (9.5) },/* Central Australian Standard */
    { "cadt",	tDAYZONE,  -HOUR (9.5) },/* Central Australian Daylight */
#endif
    { "east",	tZONE,     -HOUR (10) },	/* Eastern Australian Standard */
    { "eadt",	tDAYZONE,  -HOUR (10) },	/* Eastern Australian Daylight */
    { "gst",	tZONE,     -HOUR (10) },	/* Guam Standard, USSR Zone 9 */
    { "nzt",	tZONE,     -HOUR (12) },	/* New Zealand */
    { "nzst",	tZONE,     -HOUR (12) },	/* New Zealand Standard */
    { "nzdt",	tDAYZONE,  -HOUR (12) },	/* New Zealand Daylight */
    { "idle",	tZONE,     -HOUR (12) },	/* International Date Line East */
    {  NULL,	0,	0  }
};

/* Military timezone table. */
static TABLE const MilitaryTable[] = {
    { "a",	tZONE,	HOUR (  1) },
    { "b",	tZONE,	HOUR (  2) },
    { "c",	tZONE,	HOUR (  3) },
    { "d",	tZONE,	HOUR (  4) },
    { "e",	tZONE,	HOUR (  5) },
    { "f",	tZONE,	HOUR (  6) },
    { "g",	tZONE,	HOUR (  7) },
    { "h",	tZONE,	HOUR (  8) },
    { "i",	tZONE,	HOUR (  9) },
    { "k",	tZONE,	HOUR ( 10) },
    { "l",	tZONE,	HOUR ( 11) },
    { "m",	tZONE,	HOUR ( 12) },
    { "n",	tZONE,	HOUR (- 1) },
    { "o",	tZONE,	HOUR (- 2) },
    { "p",	tZONE,	HOUR (- 3) },
    { "q",	tZONE,	HOUR (- 4) },
    { "r",	tZONE,	HOUR (- 5) },
    { "s",	tZONE,	HOUR (- 6) },
    { "t",	tZONE,	HOUR (- 7) },
    { "u",	tZONE,	HOUR (- 8) },
    { "v",	tZONE,	HOUR (- 9) },
    { "w",	tZONE,	HOUR (-10) },
    { "x",	tZONE,	HOUR (-11) },
    { "y",	tZONE,	HOUR (-12) },
    { "z",	tZONE,	HOUR (  0) },
    { NULL,	0,	0 }
};



/* ARGSUSED */
static int yyerror(const char *unused_s)
{
	(void) unused_s;
    return 0;
}

static int ToHour(int Hours, MERIDIAN Meridian)
{
    switch (Meridian) {
    case MER24:
	if (Hours < 0 || Hours > 23)
	    return -1;
	return Hours;
    case MERam:
	if (Hours < 1 || Hours > 12)
	    return -1;
	if (Hours == 12)
	    Hours = 0;
	return Hours;
    case MERpm:
	if (Hours < 1 || Hours > 12)
	    return -1;
	if (Hours == 12)
	    Hours = 0;
	return Hours + 12;
    default:
	abort();
    }
    /* NOTREACHED */
}

static int ToYear(int Year)
{
    if (Year < 0)
	Year = -Year;

    /* XPG4 suggests that years 00-68 map to 2000-2068, and
       years 69-99 map to 1969-1999.  */
    if (Year < 69)
	Year += 2000;
    else if (Year < 100)
	Year += TM_YEAR_ORIGIN;

    return Year;
}

static int LookupWord(char *buff)
{
    register unsigned char *p;
    register unsigned char *q;
    register const TABLE *tp;
    int i;
    int abbrev;

    /* Make it lowercase. */
    for (p = (unsigned char *) buff; *p; p++)
	if (ISUPPER(*p))
	    *p += 32;

    if (strcmp(buff, "am") == 0 || strcmp(buff, "a.m.") == 0) {
	yylval.Meridian = MERam;
	return tMERIDIAN;
    }
    if (strcmp(buff, "pm") == 0 || strcmp(buff, "p.m.") == 0) {
	yylval.Meridian = MERpm;
	return tMERIDIAN;
    }

    /* See if we have an abbreviation for a month. */
    if (strlen(buff) == 3)
	abbrev = 1;
    else if (strlen(buff) == 4 && buff[3] == '.') {
	abbrev = 1;
	buff[3] = '\0';
    } else
	abbrev = 0;

    for (tp = MonthDayTable; tp->name; tp++) {
	if (abbrev) {
	    if (strncmp(buff, tp->name, 3) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
	} else if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}
    }

    for (tp = TimezoneTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    if (strcmp(buff, "dst") == 0)
	return tDST;

    for (tp = UnitsTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Strip off any plural and try the units table again. */
    i = strlen(buff) - 1;
    if (buff[i] == 's') {
	buff[i] = '\0';
	for (tp = UnitsTable; tp->name; tp++)
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
	buff[i] = 's';		/* Put back for "this" in OtherTable. */
    }

    for (tp = OtherTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Military timezones. */
    if (buff[1] == '\0' && ISALPHA((unsigned char) *buff)) {
	for (tp = MilitaryTable; tp->name; tp++)
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
    }

    /* Drop out any periods and try the timezone table again. */
    for (i = 0, p = q = (unsigned char *) buff; *q; q++)
	if (*q != '.')
	    *p++ = *q;
	else
	    i++;
    *p = '\0';
    if (i)
	for (tp = TimezoneTable; tp->name; tp++)
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }

    return tID;
}

static int yylex(void)
{
    register unsigned char c;
    register unsigned char *p;
    unsigned char buff[20];
    int Count;
    int sign;

    for (;;) {
	while (ISSPACE(*yyInput))
	    yyInput++;

	if (ISDIGIT(c = *yyInput) || c == '-' || c == '+') {
	    if (c == '-' || c == '+') {
		sign = c == '-' ? -1 : 1;
		if (!ISDIGIT(*++yyInput))
		    /* skip the '-' sign */
		    continue;
	    } else
		sign = 0;
	    for (yylval.Number = 0; ISDIGIT(c = *yyInput++);)
		yylval.Number = 10 * yylval.Number + c - '0';
	    yyInput--;

	    /*
	     * If we detect digit 'T', then it's a new ISO time.
	     * Return tNUMBER_T to indicate a number followed by 'T'.
	     *
	     * If we detect digit '.', then it's a fractional second
	     * in the ISO specs, and we return tNUMBER_DOT
	     *
	     *            --RAM, 20/05/2002
	     */

	    c = *yyInput++;

	    if (c == 'T')
		return tNUMBER_T;
	    else if (c == '.')
		return tNUMBER_DOT;
	    else
		yyInput--;

	    if (sign < 0)
		yylval.Number = -yylval.Number;
	    return sign ? tSNUMBER : tUNUMBER;
	}
	if (ISALPHA(c)) {
	    for (p = buff; (c = *yyInput++, ISALPHA(c)) || c == '.';)
		if (p < &buff[sizeof buff - 1])
		    *p++ = c;
	    *p = '\0';
	    yyInput--;
	    return LookupWord((char *) buff);
	}
	if (c != '(')
	    return *yyInput++;
	Count = 0;
	do {
	    c = *yyInput++;
	    if (c == '\0')
		return c;
	    if (c == '(')
		Count++;
	    else if (c == ')')
		Count--;
	}
	while (Count > 0);
    }
}

/*
 * date2time
 *
 * Convert date string into time_t.
 *
 * NB: was originally called getdate(), but it conflicted with a library
 * routine on Solaris.
 */
time_t date2time(const char *p, time_t now)
{
    struct tm tm, tm0, *tmp;
    time_t Start;

    yyInput = (const unsigned char *) p;
    tmp = localtime(&now);
    yyYear = tmp->tm_year + TM_YEAR_ORIGIN;
    yyMonth = tmp->tm_mon + 1;
    yyDay = tmp->tm_mday;
    yyHour = tmp->tm_hour;
    yyMinutes = tmp->tm_min;
    yySeconds = tmp->tm_sec;
    yyMeridian = MER24;
    yyRelSeconds = 0;
    yyRelMinutes = 0;
    yyRelHour = 0;
    yyRelDay = 0;
    yyRelMonth = 0;
    yyRelYear = 0;
    yyHaveDate = 0;
    yyHaveDay = 0;
    yyHaveRel = 0;
    yyHaveTime = 0;
    yyHaveZone = 0;

    if (yyparse()
	|| yyHaveTime > 1 || yyHaveZone > 1 || yyHaveDate > 1
	|| yyHaveDay > 1)
	return -1;

	ZERO(&tm);
    tm.tm_year = ToYear(yyYear) - TM_YEAR_ORIGIN + yyRelYear;
    tm.tm_mon = yyMonth - 1 + yyRelMonth;
    tm.tm_mday = yyDay + yyRelDay;
    if (yyHaveTime || (yyHaveRel && !yyHaveDate && !yyHaveDay)) {
	tm.tm_hour = ToHour(yyHour, yyMeridian);
	if (tm.tm_hour < 0)
	    return -1;
	tm.tm_min = yyMinutes;
	tm.tm_sec = yySeconds;
    } else {
	tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
    }
    tm.tm_hour += yyRelHour;
    tm.tm_min += yyRelMinutes;
    tm.tm_sec += yyRelSeconds;
    tm.tm_isdst = -1;
    tm0 = tm;

    Start = mktime(&tm);

    if (Start == (time_t) - 1) {

	/*
	 * Guard against falsely reporting errors near the time_t boundaries
	 * when parsing times in other time zones.  For example, if the min
	 * time_t value is 1970-01-01 00:00:00 UTC and we are 8 hours ahead
	 * of UTC, then the min localtime value is 1970-01-01 08:00:00; if
	 * we apply mktime to 1970-01-01 00:00:00 we will get an error, so
	 * we apply mktime to 1970-01-02 08:00:00 instead and adjust the time
	 * zone by 24 hours to compensate.  This algorithm assumes that
	 * there is no DST transition within a day of the time_t boundaries.
	 */

	if (yyHaveZone) {
	    tm = tm0;
	    if (tm.tm_year <= EPOCH - TM_YEAR_ORIGIN) {
		tm.tm_mday++;
		yyTimezone -= 24 * 60;
	    } else {
		tm.tm_mday--;
		yyTimezone += 24 * 60;
	    }
	    Start = mktime(&tm);
	}

	if (Start == (time_t) - 1)
	    return Start;
    }

    if (yyHaveDay && !yyHaveDate) {
	tm.tm_mday += ((yyDayNumber - tm.tm_wday + 7) % 7
		       + 7 * (yyDayOrdinal - (0 < yyDayOrdinal)));
	Start = mktime(&tm);
	if (Start == (time_t) - 1)
	    return Start;
    }

    if (yyHaveZone) {
	long delta = yyTimezone * 60L + diff_tm(&tm, gmtime(&Start));
	if ((Start + delta < Start) != (delta < 0))
	    return -1;		/* time_t overflow */
	Start += delta;
    }

    return Start;
}

#if	defined (TEST)

/* ARGSUSED */
int main(int ac, char *av[])
{
    char buff[MAX_BUFF_LEN + 1];
    time_t d;

    (void) printf("Enter date, or blank line to exit.\n\t> ");
    (void) fflush(stdout);

    buff[MAX_BUFF_LEN] = 0;
    while (fgets(buff, MAX_BUFF_LEN, stdin) && buff[0]) {
	time_t now;

	d = date2time(buff, time(NULL));
	if (d == -1)
	    (void) printf("Bad format - couldn't convert.\n");
	else
	    (void) printf("%d - %s", (int) d, ctime(&d));
	(void) printf("\t> ");
	(void) fflush(stdout);
    }
    exit(0);
    /* NOTREACHED */
}
#endif				/* defined (TEST) */
#line 1041 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = yyssp - yyss;
    newss = (yyss != 0)
          ? (short *)realloc(yyss, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    yyss  = newss;
    yyssp = newss + i;
    newvs = (yyvs != 0)
          ? (YYSTYPE *)realloc(yyvs, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    yystate = 0;
    *yyssp = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yyssp = yytable[yyn];
        *++yyvsp = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yyssp = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 3:
#line 220 "getdate.y"
	{
	    yyHaveTime++;
	}
break;
case 4:
#line 223 "getdate.y"
	{
	    yyHaveZone++;
	}
break;
case 5:
#line 226 "getdate.y"
	{
	    yyHaveDate++;
	}
break;
case 6:
#line 229 "getdate.y"
	{
	    yyHaveDay++;
	}
break;
case 7:
#line 232 "getdate.y"
	{
	    yyHaveRel++;
	}
break;
case 9:
#line 238 "getdate.y"
	{
	    yyHour = yyvsp[-1].Number;
	    yyMinutes = 0;
	    yySeconds = 0;
	    yyMeridian = yyvsp[0].Meridian;
	}
break;
case 10:
#line 244 "getdate.y"
	{
	    yyHour = yyvsp[-3].Number;
	    yyMinutes = yyvsp[-1].Number;
	    yySeconds = 0;
	    yyMeridian = yyvsp[0].Meridian;
	}
break;
case 11:
#line 250 "getdate.y"
	{
	    yyHour = yyvsp[-3].Number;
	    yyMinutes = yyvsp[-1].Number;
	    yyMeridian = MER24;
	    yyHaveZone++;
	    yyTimezone = (yyvsp[0].Number < 0
			  ? -yyvsp[0].Number % 100 + (-yyvsp[0].Number / 100) * 60
			  : - (yyvsp[0].Number % 100 + (yyvsp[0].Number / 100) * 60));
	}
break;
case 12:
#line 259 "getdate.y"
	{
	    yyHour = yyvsp[-5].Number;
	    yyMinutes = yyvsp[-3].Number;
	    yySeconds = yyvsp[-1].Number;
	    yyMeridian = yyvsp[0].Meridian;
	}
break;
case 13:
#line 265 "getdate.y"
	{
	    yyHour = yyvsp[-5].Number;
	    yyMinutes = yyvsp[-3].Number;
	    yySeconds = yyvsp[-1].Number;
	    yyHaveZone++;
	}
break;
case 14:
#line 271 "getdate.y"
	{
	    yyHour = yyvsp[-5].Number;
	    yyMinutes = yyvsp[-3].Number;
	    yySeconds = yyvsp[-1].Number;
		/* We ignore the fractional seconds -- RAM */
	}
break;
case 15:
#line 277 "getdate.y"
	{
	    yyHour = yyvsp[-6].Number;
	    yyMinutes = yyvsp[-4].Number;
	    yySeconds = yyvsp[-2].Number;
		/* We ignore the fractional seconds -- RAM */
	    yyHaveZone++;
	}
break;
case 16:
#line 284 "getdate.y"
	{
	    yyHour = yyvsp[-5].Number;
	    yyMinutes = yyvsp[-3].Number;
	    yySeconds = yyvsp[-1].Number;
	    yyMeridian = MER24;
	    yyHaveZone++;
	    yyTimezone = (yyvsp[0].Number < 0
			  ? -yyvsp[0].Number % 100 + (-yyvsp[0].Number / 100) * 60
			  : - (yyvsp[0].Number % 100 + (yyvsp[0].Number / 100) * 60));
	}
break;
case 17:
#line 296 "getdate.y"
	{
	    yyTimezone = yyvsp[0].Number;
	}
break;
case 18:
#line 299 "getdate.y"
	{
	    yyTimezone = yyvsp[0].Number - 60;
	}
break;
case 19:
#line 303 "getdate.y"
	{
	    yyTimezone = yyvsp[-1].Number - 60;
	}
break;
case 20:
#line 308 "getdate.y"
	{
	    /* ISO 8601 format.  +02:00 -- RAM */

		yyTimezone = yyvsp[-2].Number < 0
			  ? -yyvsp[-2].Number * 60 + yyvsp[0].Number
			  : -(yyvsp[-2].Number * 60 + yyvsp[0].Number);
	}
break;
case 21:
#line 317 "getdate.y"
	{
	    yyDayOrdinal = 1;
	    yyDayNumber = yyvsp[0].Number;
	}
break;
case 22:
#line 321 "getdate.y"
	{
	    yyDayOrdinal = 1;
	    yyDayNumber = yyvsp[-1].Number;
	}
break;
case 23:
#line 325 "getdate.y"
	{
	    yyDayOrdinal = yyvsp[-1].Number;
	    yyDayNumber = yyvsp[0].Number;
	}
break;
case 24:
#line 331 "getdate.y"
	{
	    yyMonth = yyvsp[-2].Number;
	    yyDay = yyvsp[0].Number;
	}
break;
case 25:
#line 335 "getdate.y"
	{
	  /* Interpret as YYYY/MM/DD if $1 >= 1000, otherwise as DD/MM/YYYY.
	     The goal in recognizing YYYY/MM/DD is solely to support legacy
	     machine-generated dates like those in an RCS log listing.  If
	     you want portability, use the ISO 8601 format.  */
	  if (yyvsp[-4].Number >= 1000)
	    {
	      yyYear = yyvsp[-4].Number;
	      yyMonth = yyvsp[-2].Number;
	      yyDay = yyvsp[0].Number;
	    }
	  else
	    {
	      yyDay = yyvsp[-4].Number;
	      yyMonth = yyvsp[-2].Number;
	      yyYear = yyvsp[0].Number;
	    }
	}
break;
case 26:
#line 353 "getdate.y"
	{
	    /* ISO 8601 format.  yyyy-mm-dd.  */
	    yyYear = yyvsp[-2].Number;
	    yyMonth = -yyvsp[-1].Number;
	    yyDay = -yyvsp[0].Number;
	}
break;
case 27:
#line 359 "getdate.y"
	{
	    /* ISO 8601 format.  yyyy-mm-ddT -- RAM */
	    yyYear = yyvsp[-2].Number;
	    yyMonth = -yyvsp[-1].Number;
	    yyDay = yyvsp[0].Number;
	}
break;
case 28:
#line 365 "getdate.y"
	{
	    /* e.g. 17-JUN-1992.  */
	    yyDay = yyvsp[-2].Number;
	    yyMonth = yyvsp[-1].Number;
	    yyYear = -yyvsp[0].Number;
	}
break;
case 29:
#line 371 "getdate.y"
	{
	    yyMonth = yyvsp[-1].Number;
	    yyDay = yyvsp[0].Number;
	}
break;
case 30:
#line 375 "getdate.y"
	{
	    yyMonth = yyvsp[-3].Number;
	    yyDay = yyvsp[-2].Number;
	    yyYear = yyvsp[0].Number;
	}
break;
case 31:
#line 380 "getdate.y"
	{
	    yyMonth = yyvsp[0].Number;
	    yyDay = yyvsp[-1].Number;
	}
break;
case 32:
#line 384 "getdate.y"
	{
	    yyMonth = yyvsp[-1].Number;
	    yyDay = yyvsp[-2].Number;
	    yyYear = yyvsp[0].Number;
	}
break;
case 33:
#line 391 "getdate.y"
	{
	    yyRelSeconds = -yyRelSeconds;
	    yyRelMinutes = -yyRelMinutes;
	    yyRelHour = -yyRelHour;
	    yyRelDay = -yyRelDay;
	    yyRelMonth = -yyRelMonth;
	    yyRelYear = -yyRelYear;
	}
break;
case 35:
#line 402 "getdate.y"
	{
	    yyRelYear += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 36:
#line 405 "getdate.y"
	{
	    yyRelYear += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 37:
#line 408 "getdate.y"
	{
	    yyRelYear++;
	}
break;
case 38:
#line 411 "getdate.y"
	{
	    yyRelMonth += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 39:
#line 414 "getdate.y"
	{
	    yyRelMonth += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 40:
#line 417 "getdate.y"
	{
	    yyRelMonth++;
	}
break;
case 41:
#line 420 "getdate.y"
	{
	    yyRelDay += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 42:
#line 423 "getdate.y"
	{
	    yyRelDay += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 43:
#line 426 "getdate.y"
	{
	    yyRelDay++;
	}
break;
case 44:
#line 429 "getdate.y"
	{
	    yyRelHour += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 45:
#line 432 "getdate.y"
	{
	    yyRelHour += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 46:
#line 435 "getdate.y"
	{
	    yyRelHour++;
	}
break;
case 47:
#line 438 "getdate.y"
	{
	    yyRelMinutes += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 48:
#line 441 "getdate.y"
	{
	    yyRelMinutes += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 49:
#line 444 "getdate.y"
	{
	    yyRelMinutes++;
	}
break;
case 50:
#line 447 "getdate.y"
	{
	    yyRelSeconds += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 51:
#line 450 "getdate.y"
	{
	    yyRelSeconds += yyvsp[-1].Number * yyvsp[0].Number;
	}
break;
case 52:
#line 453 "getdate.y"
	{
	    yyRelSeconds++;
	}
break;
case 53:
#line 459 "getdate.y"
	{
	    if (yyHaveTime && yyHaveDate && !yyHaveRel)
	      yyYear = yyvsp[0].Number;
	    else
	      {
		if (yyvsp[0].Number>10000)
		  {
		    yyHaveDate++;
		    yyDay= (yyvsp[0].Number)%100;
		    yyMonth= (yyvsp[0].Number/100)%100;
		    yyYear = yyvsp[0].Number/10000;
		  }
		else
		  {
		    yyHaveTime++;
		    if (yyvsp[0].Number < 100)
		      {
			yyHour = yyvsp[0].Number;
			yyMinutes = 0;
		      }
		    else
		      {
		    	yyHour = yyvsp[0].Number / 100;
		    	yyMinutes = yyvsp[0].Number % 100;
		      }
		    yySeconds = 0;
		    yyMeridian = MER24;
		  }
	      }
	  }
break;
case 54:
#line 492 "getdate.y"
	{
	    yyval.Meridian = MER24;
	  }
break;
case 55:
#line 496 "getdate.y"
	{
	    yyval.Meridian = yyvsp[0].Meridian;
	  }
break;
#line 1634 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = (short) yystate;
    *++yyvsp = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    return (1);

yyaccept:
    return (0);
}
