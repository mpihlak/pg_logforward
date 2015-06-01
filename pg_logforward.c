#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include "postgres.h"
#include "tcop/tcopprot.h"
#include "libpq/libpq.h"
#include "utils/memutils.h"
#include "miscadmin.h"
#include "postmaster/postmaster.h"
#include "postmaster/syslogger.h"
#include "mb/pg_wchar.h"

PG_MODULE_MAGIC;

#define DEFAULT_PAYLOAD_FORMAT	"json"
#define DEFAULT_FORMAT_FUNC		format_json
#define DEFAULT_SYSLOG_FACILITY	"local0"
#define MAX_MESSAGE_SIZE		8192
/*
 * RFC5424: IPv4 syslog receivers MUST be able to receive datagrams with message
 * sizes up to and including 480 octets.
 * Datagram header takes 8 octets.
 * So we are leaving room for 470 octets + 1 for terminating null byte ('\0')
 */
#define MAX_SYSLOG_MSG_SIZE     471
#define FORMATTED_TS_LEN		128
#define MAX_CUSTOM_FIELDS		32

typedef enum {
	FV_NONE = 0, FV_STR, FV_INT
} FieldValueType;

struct LogTarget;	/* Forward declaration */

typedef enum {
	FILTER_MESSAGE,						/* Filter on message text */
	FILTER_FUNCNAME,					/* Filter on funcname of ErrorReport */
	FILTER_USERNAME,
} LogFilterType;

typedef struct LogFilter {
	LogFilterType		filter_type;	/* Type of the filter */
	char			   *filter_text;	/* Filter text */
} LogFilter;

typedef void (*format_payload_t)(struct LogTarget *t, ErrorData *e, char *msgbuf);

typedef struct LogTarget {
	struct LogTarget   *next;
	const char		   *name;
	char			   *remote_ip;
	int					remote_port;
	int					log_socket;
	struct sockaddr_in	si_remote;
	char			   *log_format;
	char			   *syslog_facility;
	int					facility_id;

	/* Log filtering */
	int					min_elevel;
	List			   *filter_list;			/* Filtering conditions for this target */

	/* GUC placeholders for filters */
	char			   *_message_filter;
	char			   *_funcname_filter;
	char			   *_username_filter;

	/* Formatting function */
	format_payload_t	format_payload;
} LogTarget;

void _PG_init(void);
static void tell(const char *fmt, ...) __attribute__((format(PG_PRINTF_ATTRIBUTE, 1, 2)));
static void emit_log(ErrorData *edata);
static void format_json(struct LogTarget *t, ErrorData *edata, char *msgbuf);
static int format_syslog_prefix(struct LogTarget *t, ErrorData *edata, char *msgbuf);
static void format_netstr(struct LogTarget *t, ErrorData *edata, char *msgbuf);
static void defineStringVariable(const char *name, const char *short_desc, char **value_addr);
static void defineIntVariable(const char *name, const char *short_desc, int *value_addr);
static void add_filters(LogTarget *target, LogFilterType filter_type, char *filter_source);
static void escape_json(char **dst, size_t *max, const char *str);
static void append_string(char **dst, size_t *max, const char *src);
static void append_netstr(char **buf, size_t *max, const char *str);
static FieldValueType extract_field_value(const char *field_name, ErrorData *edata, const char **strval, int *intval);
static void append_json_str(char **buf, size_t *max, const char *key, const char *val, bool addComma);
static void append_json_int(char **buf, size_t *max, const char *key, int val, bool addComma);


static emit_log_hook_type	prev_emit_log_hook = NULL;
static LogTarget		   *log_targets = NULL;
static char				   *log_target_names = "";
static char				   *log_field_names = "";
static char				   *instance_label = "";
static char				   *log_username = NULL;
static char				   *log_database = NULL;
static char				   *log_remotehost = NULL;
static char					my_hostname[64];
static struct timeval		log_tv;
static char					log_timestamp[FORMATTED_TS_LEN];

static char				   *field_names[] = {
								"username", "database", "remotehost", "debug_query_string", "elevel",
								"funcname", "sqlerrcode", "message", "detail", "hint",
								"context", "instance_label", "timestamp",
							};

static int					n_field_names = sizeof(field_names) / sizeof(*field_names);


/* Convenience wrapper for DefineCustomStringVariable */
static void
defineStringVariable(	const char *name,
						const char *short_desc,
						char **value_addr)
{
	DefineCustomStringVariable(name,
			short_desc,
			NULL,				/* long description */
			value_addr,
			NULL,				/* bootValue */
			PGC_SIGHUP,			/* context */
			0,					/* flags parameter since 8.4 */
			NULL,				/* check_hook parameter since 9.1 */
			NULL,				/* assign hook */
			NULL				/* show hook */
			);
}

/* Convinience wrapper for DefineCustomIntVariable */
static void
defineIntVariable(	const char *name,
					const char *short_desc,
					int *value_addr)
{
	DefineCustomIntVariable(name,
			short_desc,
			NULL,				/* long description */
			value_addr,
			0, 					/* bootValue */
			0,					/* minValue */
			65535,				/* maxValue */
			PGC_SIGHUP,			/* context */
			0,					/* flags */
			NULL,				/* check_hook parameter since 9.1 */
			NULL,				/* assign hook */
			NULL				/* show hook */
			);
}

/*
 * Tell a message about pg_logforward.
 *
 * XXX: For the lack of a better place, append the messages to a file. 
 * If possible use postgres log directory. If not, cwd will have to do.
 */
static void
tell(const char *fmt, ...)
{
	FILE   *fp;
	char	logname[1024];

	snprintf(logname, sizeof(logname), "%s/pg_logforward.out",
		Log_directory ? Log_directory : ".");

	if ((fp = fopen(logname, "a")) != NULL)
	{
		char	timebuf[64];
		va_list	ap;
		time_t	t;

		time(&t);
		strftime(timebuf, sizeof(timebuf), "%c", localtime(&t));

		va_start(ap, fmt);

		fprintf(fp, "%s pg_logforward: ", timebuf);

		vfprintf(fp, fmt, ap);

		va_end(ap);
		fclose(fp);
	}
}

/*
 * Add filters from filter_source to target's filter list.
 *
 * Note: filter_source is mangled in the process.
 */
static void
add_filters(LogTarget *target, LogFilterType filter_type, char *filter_source)
{
	LogFilter  *f;
	char	   *t;
	char	   *ftstr = NULL;
	char       *tokptr = NULL;

	if (!filter_source)
		return;

	/* Sanity check filter types before adding to list */
	switch (filter_type)
	{
		case FILTER_FUNCNAME:	ftstr = "funcname"; break;
		case FILTER_MESSAGE:	ftstr = "message"; break;
		case FILTER_USERNAME:	ftstr = "username"; break;
		default:
			tell("unknown message filter type: %d\n", filter_type);
			return;
	}

	/* Split the filter_source into list items */
	for (t = strtok_r(filter_source, "|", &tokptr); t != NULL; t = strtok_r(NULL, "|", &tokptr))
	{
		f = palloc(sizeof(*f));
		f->filter_type = filter_type;
		f->filter_text = t;
		target->filter_list = lappend(target->filter_list, f);
		tell("added %s filter: %s\n", ftstr, t);
	}
}

/*
 * Module Load Callback
 */
void
_PG_init(void)
{
	LogTarget	   *tail = log_targets;
	char		   *target_names, *tgname;
	char		   *tokptr = NULL;
	int				i;
	MemoryContext	mctx;

	/* Install Hooks */
	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = emit_log;

	/* Obtain my hostname for syslogging */
	if (gethostname(my_hostname, sizeof(my_hostname)) != 0)
		snprintf(my_hostname, sizeof(my_hostname), "[unknown]");

	mctx = MemoryContextSwitchTo(TopMemoryContext);

	defineStringVariable("logforward.target_names",
						 "List of log forwarding destination names",
						 &log_target_names);
	/* No targets specified, go away */
	if (!log_target_names)
	{
		MemoryContextSwitchTo(mctx);
		return;
	}

	target_names = pstrdup(log_target_names);

	defineStringVariable("logforward.instance_label",
						 "A label to tell this PostgreSQL instance apart",
						 &instance_label);
	if (!instance_label || !instance_label[0])
	{
		char buf[64];

		snprintf(buf, sizeof(buf), "%s:%d", my_hostname, PostPortNumber);
		instance_label = pstrdup(buf);
	}

	/*
	 * Override logged fields if needed
	 */
	defineStringVariable("logforward.log_fields",
						 "Field names for customizing forwarded log",
						 &log_field_names);
	if (log_field_names && log_field_names[0])
	{
		char    *ptr, *ftok = NULL;
		char    *field_names_str = pstrdup(log_field_names);

		/* Custom fields defined, override the default list */
		n_field_names = 0;
		for (ptr = strtok_r(field_names_str, ", ", &ftok); ptr != NULL; ptr = strtok_r(NULL, ", ", &ftok))
			field_names[n_field_names++] = ptr;
	}

	/*
	 * Tell what fields we are configured to log
	 */
	tell("Logging configured for the following %d fields:\n", n_field_names);
	for (i = 0; i < n_field_names; i++)
		tell("field %d: %s\n", i, field_names[i]);

	/*
	 * Set up the log targets.
	 */
	for (tgname = strtok_r(target_names, ",", &tokptr); tgname != NULL; tgname = strtok_r(NULL, ",", &tokptr))
	{
		LogTarget  *target = palloc(sizeof(LogTarget));
		char		buf[64];

		target->name = tgname;
		target->next = NULL;
		target->remote_ip = "";
		target->remote_port = 0;
		target->min_elevel = 0;
		target->_message_filter = NULL;
		target->_funcname_filter = NULL;
		target->_username_filter = NULL;
		target->filter_list = NIL;
		target->log_format = DEFAULT_PAYLOAD_FORMAT;
		target->syslog_facility = DEFAULT_SYSLOG_FACILITY;
		target->facility_id = -1;

		/* Obtain the target specific GUC settings */
		snprintf(buf, sizeof(buf), "logforward.%s_host", tgname);
		defineStringVariable(buf, "Remote IP address where logs are forwarded",
							 &target->remote_ip);

		snprintf(buf, sizeof(buf), "logforward.%s_port", tgname);
		defineIntVariable(	buf, "Remote port where logs are forwarded",
							 &target->remote_port);

		snprintf(buf, sizeof(buf), "logforward.%s_min_elevel", tgname);
		defineIntVariable(	buf, "Minimum elevel that will be forwarded",
							 &target->min_elevel);

		snprintf(buf, sizeof(buf), "logforward.%s_funcname_filter", tgname);
		defineStringVariable(buf, "ereport __func__ names to be filtered for this target",
							 &target->_funcname_filter);

		snprintf(buf, sizeof(buf), "logforward.%s_message_filter", tgname);
		defineStringVariable(buf, "Messages to be filtered for this target",
							 &target->_message_filter);

		snprintf(buf, sizeof(buf), "logforward.%s_username_filter", tgname);
		defineStringVariable(buf, "Usernames to be filtered for this target",
							 &target->_username_filter);

		snprintf(buf, sizeof(buf), "logforward.%s_format", tgname);
		defineStringVariable(buf, "Log format for this target: json, netstr, syslog",
							 &target->log_format);

		snprintf(buf, sizeof(buf), "logforward.%s_facility", tgname);
		defineStringVariable(buf, "Syslog facility for syslog targets",
							 &target->syslog_facility);

		/*
		 * Set up the logging socket
		 */
		if (!target->remote_ip)
		{
			tell("%s: no target ip address defined.\n", tgname);
			continue;
		}

		if (!target->remote_port)
		{
			tell("%s: no target port defined.\n", tgname);
			continue;
		}

		if ((target->log_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		{
			tell("%s: cannot create socket: %s\n",
					tgname, strerror(errno));
			continue;
		}

		if (fcntl(target->log_socket, F_SETFL, O_NONBLOCK) == -1)
		{
			tell("%s: cannot set socket nonblocking: %s\n",
					tgname, strerror(errno));
			continue;
		}

		memset((char *) &target->si_remote, 0, sizeof(target->si_remote));
		target->si_remote.sin_family = AF_INET;
		target->si_remote.sin_port = htons(target->remote_port);

		if (inet_aton(target->remote_ip, &target->si_remote.sin_addr) == 0)
			tell("%s: invalid remote address: %s\n",
					tgname, target->remote_ip);

		/*
		 * Determine format for logging target.
		 */
		if (!target->log_format)
			target->log_format = DEFAULT_PAYLOAD_FORMAT;

		if (strcmp(target->log_format, "json") == 0)
			target->format_payload = format_json;
		else if (strcmp(target->log_format, "netstr") == 0)
			target->format_payload = format_netstr;
		else if (strcmp(target->log_format, "syslog") == 0)
		{
			CODE   *c;

			if (!target->syslog_facility)
				target->syslog_facility = DEFAULT_SYSLOG_FACILITY;

			/* Determine the syslog facility */
			for (c = facilitynames; c->c_name && target->facility_id < 0; c++)
				if (strcasecmp(c->c_name, target->syslog_facility) == 0)
					target->facility_id = LOG_FAC(c->c_val);

			/* No valid facility found, skip the target */
			if (target->facility_id < 0)
			{
				tell("invalid syslog facility: %s\n", target->syslog_facility);
				break;
			}
		}
		else
		{
			tell("unknown payload format (%s), using %s",
				target->log_format, DEFAULT_PAYLOAD_FORMAT);
			target->format_payload = DEFAULT_FORMAT_FUNC;
		}

		tell("forwarding to target %s: %s:%d, format: %s\n",
				tgname, target->remote_ip, target->remote_port, target->log_format);

		/* Append the new target to the list of targets */
		if (tail)
			tail->next = target;
		else
			log_targets = target;
		tail = target;

		add_filters(target, FILTER_FUNCNAME, target->_funcname_filter);
		add_filters(target, FILTER_MESSAGE, target->_message_filter);
		add_filters(target, FILTER_USERNAME, target->_username_filter);
	}

	pfree(target_names);

	MemoryContextSwitchTo(mctx);
}

/*
 * Format timestamp to string using same format as server is using with %m
 * escape. Based on function setup_formatted_log_time from elog.c
 */
static void format_log_timestamp(void)
{
	pg_time_t	stamp_time;
#if PG_VERSION_NUM <= 90100
	pg_tz		*tz;
#endif
	char		msbuf[8];
	struct pg_tm	*pglt;

	stamp_time = (pg_time_t) log_tv.tv_sec;
#if PG_VERSION_NUM <= 90100
	tz = log_timezone ? log_timezone : gmt_timezone;
	pglt = pg_localtime(&stamp_time, tz);
#else
	pglt = pg_localtime(&stamp_time, log_timezone);
#endif
	/* Leave room for milliseconds... */
	pg_strftime(log_timestamp, FORMATTED_TS_LEN, "%Y-%m-%d %H:%M:%S     %Z", pglt);

	/* 'paste' milliseconds into place... */
	sprintf(msbuf, ".%03d", (int) (log_tv.tv_usec / 1000));
	strncpy(log_timestamp + 19, msbuf, 4);
}

/*
 * Append one string to another, return the number of characters added.
 *
 * The value pointed to by max is decreased and 'dst' advanced by the number of
 * characters added.
 */
static void
append_string(char **dst, size_t *max, const char *src)
{
	size_t len;

	if (! *max || !src)
		return;

	len = strlen(src);
	if (len >= *max)
		len = *max - 1;

	strncat(*dst, src, len);
	*max -= len;
	*dst += len;
}

/*
 * Append a netstring to buf.
 * See: http://cr.yp.to/proto/netstrings.txt
 */
static void
append_netstr(char **buf, size_t *max, const char *str)
{
	char prefix[16];

	snprintf(prefix, sizeof(prefix), "%u:", str ? (unsigned)strlen(str) : 0);
	append_string(buf, max, prefix);
	append_string(buf, max, str ? str : "");
	append_string(buf, max, ",");
}

/*
 * Add a json key/value pair to the buffer.
 */
static void
append_json_str(char **buf, size_t *max, const char *key, const char *val, bool addComma)
{
	escape_json(buf, max, key);
	append_string(buf, max, ": ");
	if (val)
		escape_json(buf, max, val);
	else
		append_string(buf, max, "null");
	if (addComma)
		append_string(buf, max, ", ");
}

/*
 * Add a json key/intvalue pair to the buffer.
 */
static void
append_json_int(char **buf, size_t *max, const char *key, int val, bool addComma)
{
	char intbuf[16];

	escape_json(buf, max, key);
	append_string(buf, max, ": ");

	snprintf(intbuf, sizeof(intbuf), "%d", val);
	append_string(buf, max, intbuf);

	if (addComma)
		append_string(buf, max, ", ");
}

/*
 * Produce a JSON string literal.
 */
static void
escape_json(char **dst, size_t *max, const char *str)
{
	const char *p;
	char		buf[16];

	append_string(dst, max, "\"");
	for (p = str; *p; p++)
	{
		switch (*p)
		{
			case '\b':	append_string(dst, max, "\\b"); break;
			case '\f':	append_string(dst, max, "\\f"); break;
			case '\n':	append_string(dst, max, "\\n"); break;
			case '\r':	append_string(dst, max, "\\r"); break;
			case '\t':	append_string(dst, max, "\\t"); break;
			case '"':	append_string(dst, max, "\\\""); break;
			case '\\':	append_string(dst, max, "\\\\"); break;
			default:
				if ((unsigned char) *p < ' ')
				{
					snprintf(buf, sizeof(buf), "\\u%04x", (int) *p);
					append_string(dst, max, buf);
				}
				else
				{
					buf[0] = *p;
					buf[1] = '\0';
					append_string(dst, max, buf);
				}
				break;
		}
	}
	append_string(dst, max, "\"");
}

/*
 * Extract field value from edata structure by name.
 */
static FieldValueType extract_field_value(const char *field_name, ErrorData *edata, const char **strval, int *intval)
{
	FieldValueType rc = FV_STR;

	if      (strcmp(field_name, "username") == 0) 			*strval = log_username;
	else if (strcmp(field_name, "database") == 0) 			*strval = log_database;
	else if (strcmp(field_name, "remotehost") == 0) 		*strval = log_remotehost;
	else if (strcmp(field_name, "debug_query_string") == 0)	*strval = debug_query_string;
	else if (strcmp(field_name, "instance_label") == 0) 	*strval = instance_label;
	else if (strcmp(field_name, "timestamp") == 0) 			*strval = log_timestamp;
	else if (strcmp(field_name, "funcname") == 0) 			*strval = edata->funcname;
	else if (strcmp(field_name, "message") == 0) 			*strval = edata->message;
	else if (strcmp(field_name, "detail") == 0) 			*strval = edata->detail;
	else if (strcmp(field_name, "hint") == 0) 				*strval = edata->hint;
	else if (strcmp(field_name, "context") == 0) 			*strval = edata->context;
	else if (strcmp(field_name, "elevel") == 0)
	{
		*intval = edata->elevel;
		rc = FV_INT;
	}
	else if (strcmp(field_name, "sqlerrcode") == 0)
	{
		*intval = edata->sqlerrcode;
		rc = FV_INT;
	}
	else
		rc = FV_NONE;

	return rc;
}

/*
 * JSON format
 */
static void
format_json(struct LogTarget *target, ErrorData *edata, char *msgbuf)
{
	char	   *buf;
	size_t		len;
	int			i;

	buf = msgbuf;
	*buf = '\0';
	len = MAX_MESSAGE_SIZE;

	if (log_timestamp[0] == '\0')
		format_log_timestamp();

	append_string(&buf, &len, "{ ");

	for (i = 0; i < n_field_names; i++)
	{
		bool		last_field = (i == n_field_names - 1);
		int			intval = -1;
		int			v;
		const char *strval = NULL;

		if ((v = extract_field_value(field_names[i], edata, &strval, &intval)) == FV_STR) 
			append_json_str(&buf, &len, field_names[i], strval, !last_field);
		else if (v == FV_INT)
			append_json_int(&buf, &len, field_names[i], intval, !last_field);
	}

	append_string(&buf, &len, " }");
}

/*
 * Format the payload as set of netstrings. No fancy stuff, just
 * one field after another: elevel, sqlerrcode, user, database, host,
 * funcname, message, detail, hint, context, debug_query_string, timestamp
 */
static void
format_netstr(struct LogTarget *target, ErrorData *edata, char *msgbuf)
{
	char	   *buf = msgbuf;
	size_t		len = MAX_MESSAGE_SIZE;
	int			i;

	*buf = '\0';
	if (log_timestamp[0] == '\0')
		format_log_timestamp();

	for (i = 0; i < n_field_names; i++)
	{
		int			v, intval = -1;
		const char *strval = NULL;

		if ((v = extract_field_value(field_names[i], edata, &strval, &intval)) == FV_STR) 
			append_netstr(&buf, &len, strval);
		else if (v == FV_INT)
		{
			char	intbuf[64];

			snprintf(intbuf, sizeof(intbuf), "%d", intval);
			append_netstr(&buf, &len, intbuf);
		}
	}
}

/*
 * Format the syslog prefix
 * See: http://tools.ietf.org/html/rfc5424
 *
 * Stick to the fixed format here, ignore any field selections and customizations.
 */
static int
format_syslog_prefix(struct LogTarget *target, ErrorData *edata, char *msgbuf)
{
	int			pri, len, i;
	int			severity = -1;
	time_t		now;
	struct tm  *gmt;
	char		ts[32];

	/* Map the postgres elevel to syslog severity */
	int levels[][2] = {
		{ DEBUG1, 7 }, { INFO, 6 }, { NOTICE, 5 }, { WARNING, 4},
		{ ERROR, 3 }, { FATAL, 2 }, { PANIC, 0 },
	};

	for (i = 0; i < sizeof(levels)/sizeof(levels[0]) && severity < 0; i++)
		if (edata->elevel <= levels[i][0])
			severity = levels[i][1];

	pri = target->facility_id * 8 + severity;

	now = (time_t) log_tv.tv_sec;
	gmt = gmtime(&now);
	strftime(ts, sizeof(ts), "%F-%dT%H:%M:%SZ", gmt);

	/*
	 * Syslog message format:
	 * PRI VERSION TS HOSTNAME APPNAME PROCID MSGID SDATA MSG
	 */

	/* Header */
	len = snprintf(msgbuf, MAX_SYSLOG_MSG_SIZE, "<%d>1 %s %s postgres %d %s ",
		pri, ts, my_hostname, MyProcPid, "-");

	/* Structured data - skip for now */
	len += snprintf(msgbuf+len, MAX_SYSLOG_MSG_SIZE - len, "%s ", "-");

	/* Message payload */
	return len;
}


/*
 * Send syslog messages. Function takes care of splitting message to smaller chunks.
 */
static void
send_syslog (struct LogTarget *target, ErrorData *edata)
{
	static unsigned long	seq = 0;
	int						chunk_nr = 1;
	int						prefixlen, len;
	char					msgbuf[MAX_SYSLOG_MSG_SIZE];
	int						i;

	if (log_timestamp[0] == '\0')
		format_log_timestamp();

	prefixlen = len = format_syslog_prefix(target, edata, msgbuf);

	seq++;

	len += snprintf(msgbuf+len, MAX_SYSLOG_MSG_SIZE - len, "[%lu-%d]", seq, chunk_nr);

	for (i = 0; i < n_field_names; i++)
	{
		int				v, intval = -1;
		const char	   *strval = NULL;
		const char     *nlpos = NULL;
		int				nlindex = MAX_SYSLOG_MSG_SIZE;
		char			intbuf[64];
		char			nullbuf[10];

		v = extract_field_value(field_names[i], edata, &strval, &intval);
		if (v == FV_INT)
		{
			snprintf(intbuf, sizeof(intbuf), "%d", intval);

			strval = intbuf;
		}

		/* Add value in case it is missing */
		if (strval == NULL || strval[0] == '\0')
		{
			if (
					strcmp(field_names[i],"username") == 0 ||
					strcmp(field_names[i],"database") == 0 ||
					strcmp(field_names[i],"remotehost") == 0
			   )
				snprintf(nullbuf, sizeof(nullbuf), "[unknown]");
			else
				nullbuf[0] = '\0';

			strval = nullbuf;

		}

		/* Check newline in data field */
		if (strval != NULL)
			nlpos = strchr(strval, '\n');

		if (nlpos != NULL)
			nlindex = nlpos - strval;

		len += snprintf(msgbuf+len, Min(MAX_SYSLOG_MSG_SIZE - len, nlindex + 2), " %s", strval);

		/* Handle truncated message */
		while (len >= MAX_SYSLOG_MSG_SIZE - 1 || nlpos != NULL)
		{
			int wr_len, mb_len;

			/* Determine how many characters were written from data field */
			wr_len = Min((strlen(strval) - (len - MAX_SYSLOG_MSG_SIZE) - 1), nlindex);
			/* Check multibyte */
			mb_len = pg_mbcliplen(strval, wr_len, wr_len);
			if (mb_len < wr_len) {
				msgbuf[Min(MAX_SYSLOG_MSG_SIZE - 1,len) - (wr_len - mb_len)] = '\0';
				wr_len = mb_len;
			}
			/* Send message chunk */
			if (sendto(target->log_socket, msgbuf, strlen(msgbuf), 0,
						(struct sockaddr *) &target->si_remote, sizeof(target->si_remote)) < 0)
				tell("sendto: %s\n", strerror(errno));

			/* Start new chunk */
			chunk_nr++;

			/* Remaining data field */
			strval = strval + wr_len;

			/* Skip newline */
			if (strval[0] == '\n')
				strval++;

			/* Check newline again */
			nlpos = strchr(strval, '\n');
			if (nlpos != NULL)
				nlindex = nlpos - strval;
			else
				nlindex = MAX_SYSLOG_MSG_SIZE;

			len = prefixlen;
			len += snprintf(msgbuf+len, MAX_SYSLOG_MSG_SIZE - len, "[%lu-%d]", seq, chunk_nr);
			len += snprintf(msgbuf+len, Min(MAX_SYSLOG_MSG_SIZE - len,nlindex + 2), " %s", strval);

		}
	}

	/* Send the last part */
	if (sendto(target->log_socket, msgbuf, strlen(msgbuf), 0,
				(struct sockaddr *) &target->si_remote, sizeof(target->si_remote)) < 0)
		tell("sendto: %s\n", strerror(errno));

}


/*
 * Handler for intercepting EmitErrorReport.
 *
 * For the moment we're assuming that emit_log() needs to be
 * re-entrant. Consider a case where a signal is caught while
 * inside emit_log - the signal handler might want' to log
 * something.
 */
static void
emit_log(ErrorData *edata)
{
	char		msgbuf[MAX_MESSAGE_SIZE];
	LogTarget  *t;

	/* Call any previous hooks */
	if (prev_emit_log_hook)
		prev_emit_log_hook(edata);

	if (MyProcPort)
	{
		log_database = MyProcPort->database_name;
		log_remotehost = MyProcPort->remote_host;
		log_username = MyProcPort->user_name;
	}

	gettimeofday(&log_tv, NULL);
	log_timestamp[0] = '\0';

	/*
	 * Loop through the log targets, send the message if filter conditions are met.
	 */
	for (t = log_targets; t != NULL; t = t->next)
	{
		ListCell   *cell;
		bool		filter_match = t->filter_list ? false : true;

		/* Skip messages with too low severity */
		if (edata->elevel < t->min_elevel)
			continue;

		/* Go through message filters, if any */
        for (cell = list_head(t->filter_list); cell != NULL && !filter_match; cell = lnext(cell))
		{
			LogFilter   *f = (LogFilter *)lfirst(cell);

			if (f->filter_type == FILTER_FUNCNAME)
				filter_match = strstr(edata->funcname, f->filter_text) != NULL;
			else if (f->filter_type == FILTER_MESSAGE)
				filter_match = strstr(edata->message, f->filter_text) != NULL;
			else if (f->filter_type == FILTER_USERNAME) {
				if (log_username == NULL || *log_username == '\0')
					filter_match = strcmp("[unknown]", f->filter_text) == 0;
				else
					filter_match = strcmp(log_username, f->filter_text) == 0;
			}
		}

		/* Format the message if any of the filters match */
		if (filter_match)
		{
			/*
			 * Syslog has much smaller max message size
			 * so we use different approach for syslog messages
			 */
			if (strcmp(t->log_format, "syslog") == 0)
				send_syslog(t, edata);
			else
			{
				t->format_payload(t, edata, msgbuf);
				if (sendto(t->log_socket, msgbuf, strlen(msgbuf), 0,
						   (struct sockaddr *) &t->si_remote, sizeof(t->si_remote)) < 0)
					tell("sendto: %s\n", strerror(errno));
			}
		}
	}
}

