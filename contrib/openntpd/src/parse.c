#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 23 "parse.y"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "ntpd.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *);
int		 popfile(void);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

struct ntpd_conf		*conf;
struct sockaddr_in		 query_addr4;
struct sockaddr_in6		 query_addr6;

struct opts {
	int		weight;
	int		correction;
	int		stratum;
	int		rtable;
	char		*refstr;
} opts;
void		opts_default(void);

typedef struct {
	union {
		int64_t			 number;
		char			*string;
		struct ntp_addr_wrap	*addr;
		struct opts		 opts;
	} v;
	int lineno;
} YYSTYPE;

#line 74 "parse.c"
#define LISTEN 257
#define ON 258
#define CONSTRAINT 259
#define CONSTRAINTS 260
#define FROM 261
#define QUERY 262
#define SERVER 263
#define SERVERS 264
#define SENSOR 265
#define CORRECTION 266
#define RTABLE 267
#define REFID 268
#define STRATUM 269
#define WEIGHT 270
#define ERROR 271
#define STRING 272
#define NUMBER 273
#define YYERRCODE 256
const short yylhs[] =
	{                                        -1,
    0,    0,    0,    0,   17,   17,   17,   17,   17,   17,
   17,    1,    2,   18,    3,    3,    4,    4,    5,   19,
    6,    6,    7,    7,    8,   20,    9,    9,   10,   10,
   11,   11,   11,   11,   12,   14,   15,   16,   13,
};
const short yylen[] =
	{                                         2,
    0,    2,    3,    3,    4,    3,    3,    3,    3,    3,
    3,    1,    1,    0,    2,    0,    2,    1,    1,    0,
    2,    0,    2,    1,    1,    0,    2,    0,    2,    1,
    1,    1,    1,    1,    2,    2,    2,    2,    2,
};
const short yydefred[] =
	{                                      1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    2,
    0,    4,    0,    0,    0,    0,   12,    0,    0,    0,
    3,    0,   13,   10,    9,    6,    8,    0,    7,   11,
    0,    5,    0,    0,    0,   24,   25,    0,    0,    0,
    0,   30,   31,   32,   33,   34,    0,    0,   18,   19,
   38,   23,   35,   36,   37,   29,   39,   17,
};
const short yydgoto[] =
	{                                       1,
   18,   24,   32,   48,   49,   27,   35,   36,   30,   41,
   42,   43,   50,   44,   45,   37,   11,   33,   28,   31,
};
const short yysindex[] =
	{                                      0,
    7,   -7, -252, -254, -253, -251, -256, -256, -250,    0,
    8,    0, -256, -249, -249, -248,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -245,    0,    0,
 -255,    0, -247, -246, -245,    0,    0, -244, -242, -241,
 -255,    0,    0,    0,    0,    0, -240, -247,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
const short yyrindex[] =
	{                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   -9,   -9,  -10,
    0,   -5,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    8,    0,    0,    0,    0,    0,
    9,    0,    0,    0,    0,    0,    0,   11,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
const short yygindex[] =
	{                                      0,
   -4,   13,    0,    0,  -22,   12,    0,   -1,    0,    0,
   -6,    0,    0,    0,    0,  -29,    0,    0,    0,    0,
};
#define YYTABLESIZE 272
const short yytable[] =
	{                                      28,
   22,   46,   12,   19,   16,   13,   14,   15,   22,   16,
   38,   46,   39,   40,   34,   17,   10,   21,   27,   47,
   15,   20,   23,   26,   34,   58,   51,   25,   53,   54,
   29,   55,   57,   52,   56,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   26,    0,   26,   26,   26,
   20,   14,    2,    3,    0,    4,    5,    0,    6,    7,
    8,    9,
};
const short yycheck[] =
	{                                      10,
   10,   31,   10,    8,   10,  258,  261,  261,   13,  261,
  266,   41,  268,  269,  270,  272,   10,   10,   10,  267,
   10,  272,  272,  272,  270,   48,  273,   15,  273,  272,
   19,  273,  273,   35,   41,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  266,   -1,  268,  269,  270,
  270,  267,  256,  257,   -1,  259,  260,   -1,  262,  263,
  264,  265,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 273
#if YYDEBUG
const char * const yyname[] =
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"LISTEN","ON","CONSTRAINT",
"CONSTRAINTS","FROM","QUERY","SERVER","SERVERS","SENSOR","CORRECTION","RTABLE",
"REFID","STRATUM","WEIGHT","ERROR","STRING","NUMBER",
};
const char * const yyrule[] =
	{"$accept : grammar",
"grammar :",
"grammar : grammar '\\n'",
"grammar : grammar main '\\n'",
"grammar : grammar error '\\n'",
"main : LISTEN ON address listen_opts",
"main : QUERY FROM STRING",
"main : SERVERS address server_opts",
"main : SERVER address server_opts",
"main : CONSTRAINTS FROM url",
"main : CONSTRAINT FROM url",
"main : SENSOR STRING sensor_opts",
"address : STRING",
"url : STRING",
"$$1 :",
"listen_opts : $$1 listen_opts_l",
"listen_opts :",
"listen_opts_l : listen_opts_l listen_opt",
"listen_opts_l : listen_opt",
"listen_opt : rtable",
"$$2 :",
"server_opts : $$2 server_opts_l",
"server_opts :",
"server_opts_l : server_opts_l server_opt",
"server_opts_l : server_opt",
"server_opt : weight",
"$$3 :",
"sensor_opts : $$3 sensor_opts_l",
"sensor_opts :",
"sensor_opts_l : sensor_opts_l sensor_opt",
"sensor_opts_l : sensor_opt",
"sensor_opt : correction",
"sensor_opt : refid",
"sensor_opt : stratum",
"sensor_opt : weight",
"correction : CORRECTION NUMBER",
"refid : REFID STRING",
"stratum : STRATUM NUMBER",
"weight : WEIGHT NUMBER",
"rtable : RTABLE NUMBER",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
unsigned int yystacksize;
int yyparse(void);
#line 449 "parse.y"

void
opts_default(void)
{
	memset(&opts, 0, sizeof opts);
	opts.weight = 1;
	opts.stratum = 1;
}

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	log_warnx("%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "constraint",		CONSTRAINT},
		{ "constraints",	CONSTRAINTS},
		{ "correction",		CORRECTION},
		{ "from",		FROM},
		{ "listen",		LISTEN},
		{ "on",			ON},
		{ "query",		QUERY},
		{ "refid",		REFID},
		{ "rtable",		RTABLE},
		{ "sensor",		SENSOR},
		{ "server",		SERVER},
		{ "servers",		SERVERS},
		{ "stratum",		STRATUM},
		{ "weight",		WEIGHT}
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

u_char	*parsebuf;
int	 parseindex;
u_char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	u_char	 buf[8096];
	u_char	*p;
	int	 quotec, next, c;
	int	 token;

	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			fatal("yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				fatal("yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

struct file *
pushfile(const char *name)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("malloc");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_config(const char *filename, struct ntpd_conf *xconf)
{
	int		 errors = 0;

	conf = xconf;
	TAILQ_INIT(&conf->listen_addrs);
	TAILQ_INIT(&conf->ntp_peers);
	TAILQ_INIT(&conf->ntp_conf_sensors);
	TAILQ_INIT(&conf->constraints);

	if ((file = pushfile(filename)) == NULL) {
		return (-1);
	}
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	return (errors ? -1 : 0);
}
#line 631 "parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    unsigned int newsize;
    long sslen;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    sslen = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + sslen;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + sslen;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse(void)
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

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
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
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
#if defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(__GNUC__)
    goto yyerrlab;
#endif
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
                *++yyssp = yystate = yytable[yyn];
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
        yychar = (-1);
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
case 4:
#line 104 "parse.y"
{ file->errors++; }
break;
case 5:
#line 107 "parse.y"
{
			struct listen_addr	*la;
			struct ntp_addr		*h, *next;

			if ((h = yyvsp[-1].v.addr->a) == NULL &&
			    (host_dns(yyvsp[-1].v.addr->name, &h) == -1 || !h)) {
				yyerror("could not resolve \"%s\"", yyvsp[-1].v.addr->name);
				free(yyvsp[-1].v.addr->name);
				free(yyvsp[-1].v.addr);
				YYERROR;
			}

			for (; h != NULL; h = next) {
				next = h->next;
				la = calloc(1, sizeof(struct listen_addr));
				if (la == NULL)
					fatal("listen on calloc");
				la->fd = -1;
				la->rtable = yyvsp[0].v.opts.rtable;
				memcpy(&la->sa, &h->ss,
				    sizeof(struct sockaddr_storage));
				TAILQ_INSERT_TAIL(&conf->listen_addrs, la,
				    entry);
				free(h);
			}
			free(yyvsp[-1].v.addr->name);
			free(yyvsp[-1].v.addr);
		}
break;
case 6:
#line 135 "parse.y"
{
			struct sockaddr_in sin4;
			struct sockaddr_in6 sin6;

			sin4.sin_family = AF_INET;
			sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sin4.sin_len = sizeof(struct sockaddr_in);
			sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif

			if (inet_pton(AF_INET, yyvsp[0].v.string, &sin4.sin_addr) == 1)
				memcpy(&query_addr4, &sin4, sizeof(struct in_addr));
			else if (inet_pton(AF_INET6, yyvsp[0].v.string, &sin6.sin6_addr) == 1)
				memcpy(&query_addr6, &sin6, sizeof(struct in6_addr));
			else {
				yyerror("invalid IPv4 or IPv6 address: %s\n",
				    yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			free(yyvsp[0].v.string);
		}
break;
case 7:
#line 159 "parse.y"
{
			struct ntp_peer		*p;
			struct ntp_addr		*h, *next;

			h = yyvsp[-1].v.addr->a;
			do {
				if (h != NULL) {
					next = h->next;
					if (h->ss.ss_family != AF_INET &&
					    h->ss.ss_family != AF_INET6) {
						yyerror("IPv4 or IPv6 address "
						    "or hostname expected");
						free(h);
						free(yyvsp[-1].v.addr->name);
						free(yyvsp[-1].v.addr);
						YYERROR;
					}
					h->next = NULL;
				} else
					next = NULL;

				p = new_peer();
				p->weight = yyvsp[0].v.opts.weight;
				p->query_addr4 = query_addr4;
				p->query_addr6 = query_addr6;
				p->addr = h;
				p->addr_head.a = h;
				p->addr_head.pool = 1;
				p->addr_head.name = strdup(yyvsp[-1].v.addr->name);
				if (p->addr_head.name == NULL)
					fatal(NULL);
				if (p->addr != NULL)
					p->state = STATE_DNS_DONE;
				TAILQ_INSERT_TAIL(&conf->ntp_peers, p, entry);
				h = next;
			} while (h != NULL);

			free(yyvsp[-1].v.addr->name);
			free(yyvsp[-1].v.addr);
		}
break;
case 8:
#line 199 "parse.y"
{
			struct ntp_peer		*p;
			struct ntp_addr		*h, *next;

			p = new_peer();
			for (h = yyvsp[-1].v.addr->a; h != NULL; h = next) {
				next = h->next;
				if (h->ss.ss_family != AF_INET &&
				    h->ss.ss_family != AF_INET6) {
					yyerror("IPv4 or IPv6 address "
					    "or hostname expected");
					free(h);
					free(p);
					free(yyvsp[-1].v.addr->name);
					free(yyvsp[-1].v.addr);
					YYERROR;
				}
				h->next = p->addr;
				p->addr = h;
			}

			p->weight = yyvsp[0].v.opts.weight;
			p->query_addr4 = query_addr4;
			p->query_addr6 = query_addr6;
			p->addr_head.a = p->addr;
			p->addr_head.pool = 0;
			p->addr_head.name = strdup(yyvsp[-1].v.addr->name);
			if (p->addr_head.name == NULL)
				fatal(NULL);
			if (p->addr != NULL)
				p->state = STATE_DNS_DONE;
			TAILQ_INSERT_TAIL(&conf->ntp_peers, p, entry);
			free(yyvsp[-1].v.addr->name);
			free(yyvsp[-1].v.addr);
		}
break;
case 9:
#line 234 "parse.y"
{
			struct constraint	*p;
			struct ntp_addr		*h, *next;

			h = yyvsp[0].v.addr->a;
			do {
				if (h != NULL) {
					next = h->next;
					if (h->ss.ss_family != AF_INET &&
					    h->ss.ss_family != AF_INET6) {
						yyerror("IPv4 or IPv6 address "
						    "or hostname expected");
						free(h);
						free(yyvsp[0].v.addr->name);
						free(yyvsp[0].v.addr->path);
						free(yyvsp[0].v.addr);
						YYERROR;
					}
					h->next = NULL;
				} else
					next = NULL;

				p = new_constraint();
				p->addr = h;
				p->addr_head.a = h;
				p->addr_head.pool = 1;
				p->addr_head.name = strdup(yyvsp[0].v.addr->name);
				p->addr_head.path = strdup(yyvsp[0].v.addr->path);
				if (p->addr_head.name == NULL ||
				    p->addr_head.path == NULL)
					fatal(NULL);
				if (p->addr != NULL)
					p->state = STATE_DNS_DONE;
				constraint_add(p);
				h = next;
			} while (h != NULL);

			free(yyvsp[0].v.addr->name);
			free(yyvsp[0].v.addr);
		}
break;
case 10:
#line 274 "parse.y"
{
			struct constraint	*p;
			struct ntp_addr		*h, *next;

			p = new_constraint();
			for (h = yyvsp[0].v.addr->a; h != NULL; h = next) {
				next = h->next;
				if (h->ss.ss_family != AF_INET &&
				    h->ss.ss_family != AF_INET6) {
					yyerror("IPv4 or IPv6 address "
					    "or hostname expected");
					free(h);
					free(p);
					free(yyvsp[0].v.addr->name);
					free(yyvsp[0].v.addr->path);
					free(yyvsp[0].v.addr);
					YYERROR;
				}
				h->next = p->addr;
				p->addr = h;
			}

			p->addr_head.a = p->addr;
			p->addr_head.pool = 0;
			p->addr_head.name = strdup(yyvsp[0].v.addr->name);
			p->addr_head.path = strdup(yyvsp[0].v.addr->path);
			if (p->addr_head.name == NULL ||
			    p->addr_head.path == NULL)
				fatal(NULL);
			if (p->addr != NULL)
				p->state = STATE_DNS_DONE;
			constraint_add(p);
			free(yyvsp[0].v.addr->name);
			free(yyvsp[0].v.addr);
		}
break;
case 11:
#line 309 "parse.y"
{
			struct ntp_conf_sensor	*s;

			s = new_sensor(yyvsp[-1].v.string);
			s->weight = yyvsp[0].v.opts.weight;
			s->correction = yyvsp[0].v.opts.correction;
			s->refstr = yyvsp[0].v.opts.refstr;
			s->stratum = yyvsp[0].v.opts.stratum;
			free(yyvsp[-1].v.string);
			TAILQ_INSERT_TAIL(&conf->ntp_conf_sensors, s, entry);
		}
break;
case 12:
#line 322 "parse.y"
{
			if ((yyval.v.addr = calloc(1, sizeof(struct ntp_addr_wrap))) ==
			    NULL)
				fatal(NULL);
			host(yyvsp[0].v.string, &yyval.v.addr->a);
			yyval.v.addr->name = yyvsp[0].v.string;
		}
break;
case 13:
#line 331 "parse.y"
{
			char	*hname, *path;

			if ((yyval.v.addr = calloc(1, sizeof(struct ntp_addr_wrap))) ==
			    NULL)
				fatal("calloc");

			if (strncmp("https://", yyvsp[0].v.string,
			    strlen("https://")) != 0) {
				host(yyvsp[0].v.string, &yyval.v.addr->a);
				yyval.v.addr->name = yyvsp[0].v.string;
			} else {
				hname = yyvsp[0].v.string + strlen("https://");

				path = hname + strcspn(hname, "/\\");
				if (*path != '\0') {
					if ((yyval.v.addr->path = strdup(path)) == NULL)
						fatal("strdup");
					*path = '\0';
				}
				host(hname, &yyval.v.addr->a);
				if ((yyval.v.addr->name = strdup(hname)) == NULL)
					fatal("strdup");
			}
			if (yyval.v.addr->path == NULL &&
			    (yyval.v.addr->path = strdup("/")) == NULL)
				fatal("strdup");
		}
break;
case 14:
#line 361 "parse.y"
{ opts_default(); }
break;
case 15:
#line 363 "parse.y"
{ yyval.v.opts = opts; }
break;
case 16:
#line 364 "parse.y"
{ opts_default(); yyval.v.opts = opts; }
break;
case 20:
#line 372 "parse.y"
{ opts_default(); }
break;
case 21:
#line 374 "parse.y"
{ yyval.v.opts = opts; }
break;
case 22:
#line 375 "parse.y"
{ opts_default(); yyval.v.opts = opts; }
break;
case 26:
#line 383 "parse.y"
{ opts_default(); }
break;
case 27:
#line 385 "parse.y"
{ yyval.v.opts = opts; }
break;
case 28:
#line 386 "parse.y"
{ opts_default(); yyval.v.opts = opts; }
break;
case 35:
#line 397 "parse.y"
{
			if (yyvsp[0].v.number < -127000000 || yyvsp[0].v.number > 127000000) {
				yyerror("correction must be between "
				    "-127000000 and 127000000 microseconds");
				YYERROR;
			}
			opts.correction = yyvsp[0].v.number;
		}
break;
case 36:
#line 407 "parse.y"
{
			size_t l = strlen(yyvsp[0].v.string);

			if (l < 1 || l > 4) {
				yyerror("refid must be 1 to 4 characters");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			opts.refstr = yyvsp[0].v.string;
		}
break;
case 37:
#line 419 "parse.y"
{
			if (yyvsp[0].v.number < 1 || yyvsp[0].v.number > 15) {
				yyerror("stratum must be between "
				    "1 and 15");
				YYERROR;
			}
			opts.stratum = yyvsp[0].v.number;
		}
break;
case 38:
#line 429 "parse.y"
{
			if (yyvsp[0].v.number < 1 || yyvsp[0].v.number > 10) {
				yyerror("weight must be between 1 and 10");
				YYERROR;
			}
			opts.weight = yyvsp[0].v.number;
		}
break;
case 39:
#line 436 "parse.y"
{
#ifdef RT_TABLEID_MAX
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > RT_TABLEID_MAX) {
				yyerror("rtable must be between 1"
				    " and RT_TABLEID_MAX");
				YYERROR;
			}
#endif
			opts.rtable = yyvsp[0].v.number;
		}
break;
#line 1198 "parse.c"
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
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
