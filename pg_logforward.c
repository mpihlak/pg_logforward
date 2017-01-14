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
	bool				enabled;
	char			   *remote_ip;
	int					remote_port;
	struct sockaddr_in	si_remote;
	char			   *log_format;
	char			   *syslog_facility;
	int					facility_id;

	/* Log fields */
	char			   *field_names[MAX_CUSTOM_FIELDS];
	int					n_field_names;

	/* Log filtering */
	int					min_elevel;
	List			   *filter_list;			/* Filtering conditions for this target */

	/* GUC placeholder for log fields */
	char			   *guc_log_fields;

	/* GUC placeholders for filters */
	char			   *guc_message_filter;
	char			   *guc_funcname_filter;
	char			   *guc_username_filter;

	/* Modifiable copies for GUC placeholders */
	char			   *log_fields;
	char			   *message_filter;
	char			   *funcname_filter;
	char			   *username_filter;

	/* Formatting function */
	format_payload_t	format_payload;
} LogTarget;

static bool check_target_names(char **newval, void **extra, GucSource source);
void setup_log_targets(void);
void _PG_init(void);
static void tell(const char *fmt, ...) __attribute__((format(PG_PRINTF_ATTRIBUTE, 1, 2)));
static void emit_log(ErrorData *edata);
static void format_json(struct LogTarget *t, ErrorData *edata, char *msgbuf);
static int format_syslog_prefix(struct LogTarget *t, ErrorData *edata, char *msgbuf);
static void send_syslog (struct LogTarget *target, ErrorData *edata);
static void format_netstr(struct LogTarget *t, ErrorData *edata, char *msgbuf);
static void defineStringVariable(const char *name, const char *short_desc, char **value_addr);
static void defineIntVariable(const char *name, const char *short_desc, int *value_addr);
static void add_filters(LogTarget *target, LogFilterType filter_type, char *guc_filter_source, char **filter_source);
static void escape_json(char **dst, size_t *max, const char *str);
static void append_string(char **dst, size_t *max, const char *src);
static void append_netstr(char **buf, size_t *max, const char *str);
static FieldValueType extract_field_value(const char *field_name, ErrorData *edata, const char **strval, int *intval);
static void append_json_str(char **buf, size_t *max, const char *key, const char *val, bool addComma);
static void append_json_int(char **buf, size_t *max, const char *key, int val, bool addComma);
static int append_syslog_string(char *buf, const char **value, size_t *len);


static emit_log_hook_type	prev_emit_log_hook = NULL;
static int					log_socket;
static LogTarget		   *log_targets = NULL;
static char				   *log_target_names = "";
static char				   *instance_label = "";
static char				   *log_username = NULL;
static char				   *log_database = NULL;
static char				   *log_remotehost = NULL;
static char					my_hostname[64];
static struct timeval		log_tv;
static char					log_timestamp[FORMATTED_TS_LEN];
static bool					got_sighup = false;

static const char		   *default_field_names[] = {
								"username", "database", "remotehost", "debug_query_string", "elevel",
								"funcname", "sqlerrcode", "message", "detail", "hint",
								"context", "instance_label", "timestamp",
							};

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

	/* Tell only if postmaster */
	if (IsUnderPostmaster || !IsPostmasterEnvironment)
		return;

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
add_filters(LogTarget *target, LogFilterType filter_type, char *guc_filter_source, char **filter_source)
{
	LogFilter  *f;
	char	   *t;
	char	   *ftstr = NULL;
	char       *tokptr = NULL;

	if (*filter_source)
	{
		pfree(*filter_source);
		*filter_source = NULL;
	}

	if (!guc_filter_source)
		return;

	*filter_source = pstrdup(guc_filter_source);

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
	for (t = strtok_r(*filter_source, "|", &tokptr); t != NULL; t = strtok_r(NULL, "|", &tokptr))
	{
		f = palloc(sizeof(*f));
		f->filter_type = filter_type;
		f->filter_text = t;
		target->filter_list = lappend(target->filter_list, f);
		tell("added %s filter: %s\n", ftstr, t);
	}
}

/*
 * Check hook for logforward.target_names. Although logforward.target_names cannot be changed
 * without restart it is used for reloading all the other parameters. The problem is that
 * other parameters (except instance_label) are dynamic and even if we could create a hook
 * for those parameters we do not know which target to modify.
 * So instead, we will set a flag here and reload all the parameters on next emit_log.
 * Also, we cannot reload all the dynamic parameters inside this hook because we do not know
 * in which order dynamic parameters are loaded from conf file.
 */
static bool
check_target_names(char **newval, void **extra, GucSource source)
{

	got_sighup = true;
	return true;
}

/* Setup log targets */
void setup_log_targets(void)
{
	LogTarget	   *t;
	MemoryContext   mctx;
	int				i;

	mctx = MemoryContextSwitchTo(TopMemoryContext);

	for (t = log_targets; t != NULL; t = t->next)
	{
		/* Disable log target */
		t->enabled = false;

		/* Set remote host and port */
		if (!t->remote_ip)
		{
			tell("%s: no target ip address defined.\n", t->name);
			continue;
		}

		if (!t->remote_port)
		{
			tell("%s: no target port defined.\n", t->name);
			continue;
		}

		memset((char *) &t->si_remote, 0, sizeof(t->si_remote));
		t->si_remote.sin_family = AF_INET;
		t->si_remote.sin_port = htons(t->remote_port);

		if (inet_aton(t->remote_ip, &t->si_remote.sin_addr) == 0)
		{
			tell("%s: invalid remote address: %s\n",
					t->name, t->remote_ip);
			continue;
		}

		/*
		 * Determine format for logging target.
		 */
		if (!t->log_format)
			t->log_format = DEFAULT_PAYLOAD_FORMAT;

		if (strcmp(t->log_format, "json") == 0)
			t->format_payload = format_json;
		else if (strcmp(t->log_format, "netstr") == 0)
			t->format_payload = format_netstr;
		else if (strcmp(t->log_format, "syslog") == 0)
		{
			CODE   *c;

			if (!t->syslog_facility)
				t->syslog_facility = DEFAULT_SYSLOG_FACILITY;

			/* Determine the syslog facility */
			for (c = facilitynames; c->c_name && t->facility_id < 0; c++)
				if (strcasecmp(c->c_name, t->syslog_facility) == 0)
					t->facility_id = LOG_FAC(c->c_val);

			/* No valid facility found, skip the target */
			if (t->facility_id < 0)
			{
				tell("invalid syslog facility: %s\n", t->syslog_facility);
				continue;
			}
		}
		else
		{
			tell("unknown payload format (%s), using %s",
				t->log_format, DEFAULT_PAYLOAD_FORMAT);
			t->format_payload = DEFAULT_FORMAT_FUNC;
		}

		tell("forwarding to target %s: %s:%d, format: %s\n",
				t->name, t->remote_ip, t->remote_port, t->log_format);

		/* Set logged fields */
		if (t->log_fields)
		{
			pfree(t->log_fields);
			t->log_fields = NULL;
		}

		if (t->guc_log_fields && t->guc_log_fields[0])
		{
			/* Custom fields defined, override the default list */
			char    *ptr, *ftok = NULL;

			/* Create modifiable copy */
			t->log_fields = pstrdup(t->guc_log_fields);

			t->n_field_names = 0;
			for (ptr = strtok_r(t->log_fields, ", ", &ftok); ptr != NULL; ptr = strtok_r(NULL, ", ", &ftok))
			{
				if (t->n_field_names == MAX_CUSTOM_FIELDS)
				{
					tell("max custom field limit(%d) has been reached\n", MAX_CUSTOM_FIELDS);
					break;
				}

				t->field_names[t->n_field_names++] = ptr;
			}
		}
		else
		{
			/* Reset to defaults */
			memcpy(t->field_names, default_field_names, sizeof(default_field_names));
			t->n_field_names = sizeof(default_field_names) / sizeof(*default_field_names);
		}

		/*
		 * Tell what fields we are configured to log
		 */
		tell("forwarding to target %s following %d fields:\n", t->name, t->n_field_names);
		for (i = 0; i < t->n_field_names; i++)
			tell("field %d: %s\n", i, t->field_names[i]);

		/* Enough data available to enable the target */
		t->enabled = true;

		/* Reset filters */
		list_free_deep(t->filter_list);
		t->filter_list = NIL;

		add_filters(t, FILTER_FUNCNAME, t->guc_funcname_filter, &t->funcname_filter);
		add_filters(t, FILTER_MESSAGE, t->guc_message_filter, &t->message_filter);
		add_filters(t, FILTER_USERNAME, t->guc_username_filter, &t->username_filter);
	}

	MemoryContextSwitchTo(mctx);

	got_sighup = false;
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
	MemoryContext	mctx;

	/* Install Hooks */
	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = emit_log;

	/* Obtain my hostname for syslogging */
	if (gethostname(my_hostname, sizeof(my_hostname)) != 0)
		snprintf(my_hostname, sizeof(my_hostname), "[unknown]");

	mctx = MemoryContextSwitchTo(TopMemoryContext);

	DefineCustomStringVariable("logforward.target_names",
			"List of log forwarding destination names",
			NULL,
			&log_target_names,
			NULL,
			PGC_POSTMASTER,
			0,
			check_target_names,
			NULL,
			NULL
			);

	/* No targets specified, go away */
	if (!log_target_names)
	{
		MemoryContextSwitchTo(mctx);
		return;
	}

	/* Create logging socket */
	if ((log_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		tell("cannot create socket: %s\n", strerror(errno));
		return;
	}
	if (fcntl(log_socket, F_SETFL, O_NONBLOCK) == -1)
	{
		tell("cannot set socket nonblocking: %s\n", strerror(errno));
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
	 * Create log targets.
	 */
	for (tgname = strtok_r(target_names, ",", &tokptr); tgname != NULL; tgname = strtok_r(NULL, ",", &tokptr))
	{
		LogTarget  *target = palloc(sizeof(LogTarget));
		char		buf[64];

		target->name = tgname;
		target->enabled = false;
		target->next = NULL;
		target->remote_ip = "";
		target->remote_port = 0;
		target->min_elevel = 0;
		target->guc_message_filter = NULL;
		target->message_filter = NULL;
		target->guc_funcname_filter = NULL;
		target->funcname_filter = NULL;
		target->guc_username_filter = NULL;
		target->username_filter = NULL;
		target->filter_list = NIL;
		target->log_format = DEFAULT_PAYLOAD_FORMAT;
		target->syslog_facility = DEFAULT_SYSLOG_FACILITY;
		target->facility_id = -1;
		target->guc_log_fields = NULL;
		target->log_fields = NULL;

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
							 &target->guc_funcname_filter);

		snprintf(buf, sizeof(buf), "logforward.%s_message_filter", tgname);
		defineStringVariable(buf, "Messages to be filtered for this target",
							 &target->guc_message_filter);

		snprintf(buf, sizeof(buf), "logforward.%s_username_filter", tgname);
		defineStringVariable(buf, "Usernames to be filtered for this target",
							 &target->guc_username_filter);

		snprintf(buf, sizeof(buf), "logforward.%s_format", tgname);
		defineStringVariable(buf, "Log format for this target: json, netstr, syslog",
							 &target->log_format);

		snprintf(buf, sizeof(buf), "logforward.%s_facility", tgname);
		defineStringVariable(buf, "Syslog facility for syslog targets",
							 &target->syslog_facility);

		snprintf(buf, sizeof(buf), "logforward.%s_log_fields", tgname);
		defineStringVariable(buf, "Field names for customizing forwarded log",
							 &target->guc_log_fields);

		/* Append the new target to the list of targets */
		if (tail)
			tail->next = target;
		else
			log_targets = target;
		tail = target;
	}

	MemoryContextSwitchTo(mctx);

	setup_log_targets();


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
 * Append string to syslog message buffer. Checks newline and multibyte.
 * Return 1 if message was split otherwise 0.
 */
static int
append_syslog_string(char *buf, const char **value, size_t *len)
{
	int retval = 1;
	char *buf_start = buf;
	int initial_len = *len;
	int wr_len, mb_diff;

    while (1)
    {
		if (*len >= MAX_SYSLOG_MSG_SIZE -1)
		{
			/* Check multibyte */
			wr_len = *len - initial_len;
			mb_diff = wr_len - pg_mbcliplen(buf_start, wr_len, wr_len);
			if (mb_diff > 0)
			{
				buf -= mb_diff;
				*len-= mb_diff;
				*value -= mb_diff;
			}
			break;
		}

        if (**value == '\0')
		{
			retval = 0;
            break;
		}

        if (**value == '\n')
        {
			/* Skip newline */
			(*value)++;
            break;
        }

        *buf++ = *(*value)++;

        (*len)++;
    }

    *buf = '\0';

    return retval;
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

	append_string(&buf, &len, "{ ");

	for (i = 0; i < target->n_field_names; i++)
	{
		bool		last_field = (i == target->n_field_names - 1);
		int			intval = -1;
		int			v;
		const char *strval = NULL;

		if (strcmp(target->field_names[i], "timestamp") == 0 && log_timestamp[0] == '\0')
			format_log_timestamp();

		if ((v = extract_field_value(target->field_names[i], edata, &strval, &intval)) == FV_STR) 
			append_json_str(&buf, &len, target->field_names[i], strval, !last_field);
		else if (v == FV_INT)
			append_json_int(&buf, &len, target->field_names[i], intval, !last_field);
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

	for (i = 0; i < target->n_field_names; i++)
	{
		int			v, intval = -1;
		const char *strval = NULL;

		if (strcmp(target->field_names[i], "timestamp") == 0 && log_timestamp[0] == '\0')
			format_log_timestamp();

		if ((v = extract_field_value(target->field_names[i], edata, &strval, &intval)) == FV_STR) 
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
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

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
	size_t					prefixlen, len;
	char					msgbuf[MAX_SYSLOG_MSG_SIZE];
	int						i;

	prefixlen = len = format_syslog_prefix(target, edata, msgbuf);

	seq++;

	len += snprintf(msgbuf+len, MAX_SYSLOG_MSG_SIZE - len, "[%lu-%d]", seq, chunk_nr);

	/*
	 * We have doubled the field number to add space before each field.
	 * If we have odd field number then field will be added.
	 */
	for (i = 0; i < target->n_field_names * 2; i++)
	{
		int				v, intval = -1;
		const char	   *strval = NULL;
		char			intbuf[64];
		char			tmpbuf[10] = " ";

		if (i % 2)
		{
			int fn_i = i/2;

			if (strcmp(target->field_names[fn_i], "timestamp") == 0 && log_timestamp[0] == '\0')
				format_log_timestamp();

			v = extract_field_value(target->field_names[fn_i], edata, &strval, &intval);
			if (v == FV_INT)
			{
				snprintf(intbuf, sizeof(intbuf), "%d", intval);
				strval = intbuf;
			}

			/* Add value in case it is missing */
			if (strval == NULL || *strval == '\0')
			{
				if (
						strcmp(target->field_names[fn_i],"username") == 0 ||
						strcmp(target->field_names[fn_i],"database") == 0 ||
						strcmp(target->field_names[fn_i],"remotehost") == 0
				   )
					snprintf(tmpbuf, sizeof(tmpbuf), "[unknown]");
				else
					tmpbuf[0] = '\0';

				strval = tmpbuf;
			}
		}
		else
		{
			/* Add space before each new field */
			strval = tmpbuf;
		}

		while (append_syslog_string(msgbuf+len,&strval,&len))
		{
			/* Send message chunk */
			if (sendto(log_socket, msgbuf, len, 0,
						(struct sockaddr *) &target->si_remote, sizeof(target->si_remote)) < 0)
				tell("sendto: %s\n", strerror(errno));

			/* Start new chunk */
			chunk_nr++;

			len = prefixlen;
			len += snprintf(msgbuf+len, MAX_SYSLOG_MSG_SIZE - len, "[%lu-%d] ", seq, chunk_nr);
		}
	}

	/* Send the last part */
	if (sendto(log_socket, msgbuf, len, 0,
				(struct sockaddr *) &target->si_remote, sizeof(target->si_remote)) < 0)
		tell("sendto: %s\n", strerror(errno));

}


/*
 * Handler for intercepting EmitErrorReport.
 *
 */
static void
emit_log(ErrorData *edata)
{
	char		msgbuf[MAX_MESSAGE_SIZE];
	LogTarget  *t;

	/* Call any previous hooks */
	if (prev_emit_log_hook)
		prev_emit_log_hook(edata);


	if (got_sighup)
		setup_log_targets();

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

		/* Skip disabled targets */
		if (!t->enabled)
			continue;

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
				if (sendto(log_socket, msgbuf, strlen(msgbuf), 0,
						   (struct sockaddr *) &t->si_remote, sizeof(t->si_remote)) < 0)
					tell("sendto: %s\n", strerror(errno));
			}
		}
	}
}

