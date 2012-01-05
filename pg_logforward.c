#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include <json/json.h>

#include "postgres.h"
#include "tcop/tcopprot.h"
#include "libpq/libpq.h"
#include "utils/memutils.h"
#include "miscadmin.h"

PG_MODULE_MAGIC;

#define DEFAULT_SYSLOG_FACILITY	"local0"
#define DEFAULT_PAYLOAD_FORMAT	"json"
#define DEFAULT_FORMAT_FUNC		format_json

#define MAX_SYSLOG_MESSAGE		8192
#define MAX_NETSTR_MESSAGE		8192

#define JSONSTR(s)	json_object_new_string((s) ? (s) : "")
#define NETSTR(buf, size, value) \
					snprintf(buf, size, "%u:%s,", \
						(unsigned)((value) ? strlen(value) : 0), \
						(value) ? (value) : "")

typedef const char *(*format_payload_t)(ErrorData *e);

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
	char			   *message_filter;

	/* Formatting functions */
	format_payload_t	format_payload;
} LogTarget;


void _PG_init(void);
static void emit_log(ErrorData *edata);
static const char *format_json(ErrorData *edata);
static const char *format_syslog(ErrorData *edata);
static const char *format_netstr(ErrorData *edata);
static void defineStringVariable(const char *name, const char *short_desc, char **value_addr);
static void defineIntVariable(const char *name, const char *short_desc, int *value_addr);


static emit_log_hook_type	prev_emit_log_hook = NULL;
static LogTarget		   *log_targets = NULL;
static char				   *log_target_names = "";
static char				   *log_username = NULL;
static char				   *log_database = NULL;
static char				   *log_hostname = NULL;
static char					my_hostname[64];


/* Convenience wrapper for DefineCustomStringVariable */
static void defineStringVariable(	const char *name,
									const char *short_desc,
									char **value_addr)
{
	DefineCustomStringVariable(name,
			short_desc,
			NULL,
			value_addr,
#if PG_VERSION_NUM >= 80400
			NULL,				/* bootValue since 8.4 */
#endif
#if PG_VERSION_NUM >= 80400
			PGC_BACKEND,
			0,					/* flags parameter since 8.4 */
#else
			PGC_USERSET,		/* 8.3 only allows USERSET custom params */
#endif
#if PG_VERSION_NUM >= 90100
			NULL,				/* check_hook parameter since 9.1 */
#endif
			NULL,
			NULL);
}

/* Convinience wrapper for DefineCustomIntVariable */
static void defineIntVariable(	const char *name,
								const char *short_desc,
								int *value_addr)
{
	DefineCustomIntVariable(name,
			short_desc,
			NULL,
			value_addr,
#if PG_VERSION_NUM >= 80400
			-1, 				/* bootValue since 8.4 */
#endif
			1,
			65535,
#if PG_VERSION_NUM >= 80400
			PGC_BACKEND,
			0,
#else
			PGC_USERSET,		/* 8.3 only allows USERSET custom params */
#endif
#if PG_VERSION_NUM >= 90100
			NULL,				/* check_hook parameter since 9.1 */
#endif
			NULL,
			NULL);
}

/*
 * Module Load Callback
 */
void
_PG_init(void)
{
	LogTarget	   *tail = log_targets;
	char		   *tgname;
	char			target_names[1024];
	MemoryContext	mctx;

	/* Install Hooks */
	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = emit_log;

	mctx = MemoryContextSwitchTo(TopMemoryContext);

	defineStringVariable("logforward.target_names",
						 "List of log forwarding destination names",
						 &log_target_names);

	/* Use a local copy for string tokenization */
	strncpy(target_names, log_target_names, sizeof(target_names));
	target_names[sizeof(target_names)-1] = '\0';

	/* Obtain my hostname for syslogging */
	if (gethostname(my_hostname, sizeof(my_hostname)) != 0)
		snprintf(my_hostname, sizeof(my_hostname), "[unknown]");

	/*
	 * Set up the log targets.
	 */
	for (tgname = strtok(target_names, ","); tgname != NULL;
		 tgname = strtok(NULL, ","))
	{
		LogTarget  *target = palloc(sizeof(LogTarget));
		char		buf[64];

		target->name = tgname;
		target->next = NULL;
		target->min_elevel = 0;
		target->message_filter = NULL;
		target->syslog_facility = DEFAULT_SYSLOG_FACILITY;
		target->facility_id = -1;
		target->log_format = DEFAULT_PAYLOAD_FORMAT;

		/* Obtain the target specific GUC settings */
		snprintf(buf, sizeof(buf), "logforward.%s_host", tgname);
		defineStringVariable(buf, 
							 "Remote IP address where logs are forwarded",
							 &target->remote_ip);
		if (!target->remote_ip)
		{
			fprintf(stderr, "pg_logforward: %s: no target ip address defined.\n", tgname);
			continue;
		}

		snprintf(buf, sizeof(buf), "logforward.%s_port", tgname);
		defineIntVariable(	buf,
							 "Remote port where logs are forwarded",
							 &target->remote_port);
		if (!target->remote_port)
		{
			fprintf(stderr, "pg_logforward: %s: no target port defined.\n", tgname);
			continue;
		}

		snprintf(buf, sizeof(buf), "logforward.%s_min_elevel", tgname);
		defineIntVariable(	buf,
							 "Minimum elevel that will be forwarded",
							 &target->min_elevel);

		snprintf(buf, sizeof(buf), "logforward.%s_message_filter", tgname);
		defineStringVariable(buf, 
							 "Messages to be filtered for this target",
							 &target->message_filter);

		snprintf(buf, sizeof(buf), "logforward.%s_format", tgname);
		defineStringVariable(buf, 
							 "Log format for this target: json, netstr, syslog",
							 &target->log_format);

		snprintf(buf, sizeof(buf), "logforward.%s_facility", tgname);
		defineStringVariable(buf, 
							 "Syslog facility for syslog targets",
							 &target->syslog_facility);

		/* Set up the logging socket */
		if ((target->log_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		{
			fprintf(stderr, "pg_logforward: %s: cannot create socket: %s\n",
					tgname, strerror(errno));
			continue;
		}

		if (fcntl(target->log_socket, F_SETFL, O_NONBLOCK) == -1)
		{
			fprintf(stderr, "pg_logforward: %s: cannot set socket nonblocking: %s\n",
					tgname, strerror(errno));
			continue;
		}

		memset((char *) &target->si_remote, 0, sizeof(target->si_remote));
		target->si_remote.sin_family = AF_INET;
		target->si_remote.sin_port = htons(target->remote_port);

		if (inet_aton(target->remote_ip, &target->si_remote.sin_addr) == 0)
			fprintf(stderr, "pg_logforward: %s: invalid remote address: %s\n",
					tgname, target->remote_ip);

		/* Determine the log format */
		if (strcmp(target->log_format, "json") == 0)
			target->format_payload = format_json;
		else if (strcmp(target->log_format, "netstr") == 0)
			target->format_payload = format_netstr;
		else if (strcmp(target->log_format, "syslog") == 0)
		{
			CODE   *c;
			target->format_payload = format_syslog;

			/* Determine the syslog facility */
			for (c = facilitynames; c->c_name && target->facility_id < 0; c++)
				if (strcasecmp(c->c_name, target->syslog_facility) == 0)
					target->facility_id = c->c_val;
			
			/* No valid facility found, skip the target */
			if (target->facility_id < 0)
			{
				fprintf(stderr, "pg_logforward: invalid syslog facility: %s\n",
					target->syslog_facility);
				break;
			}
		}
		else
		{
			fprintf(stderr, "pg_logforward: unknown payload format (%s), using %s",
				target->log_format, DEFAULT_PAYLOAD_FORMAT);
			target->format_payload = DEFAULT_FORMAT_FUNC;
		}

		fprintf(stderr, "pg_logforward: forwarding to target %s: %s:%d, format: %s\n",
				tgname, target->remote_ip, target->remote_port, target->log_format);

		/* Append the new target to the list of targets */
		if (tail)
			tail->next = target;
		else
			log_targets = target;
		tail = target;
	}

	MemoryContextSwitchTo(mctx);
}

/*
 * Format the edata as JSON
 */
static const char *format_json(ErrorData *edata)
{
	static json_object	*msg = NULL;

	/*
	 * Release any leftovers from previous formatting. 
	 *
	 * Note that there is some point in keeping the msg object
	 * around in case there are multiple JSON targets. It is
	 * easy enough to do, but for now don't bother.
	 */
	if (msg)
		json_object_put(msg);

	msg = json_object_new_object();

	json_object_object_add(msg, "username", JSONSTR(log_username));
	json_object_object_add(msg, "database", JSONSTR(log_database));
	json_object_object_add(msg, "remotehost", JSONSTR(log_hostname));
	json_object_object_add(msg, "debug_query_string", JSONSTR(debug_query_string));
	json_object_object_add(msg, "elevel", json_object_new_int(edata->elevel));
	json_object_object_add(msg, "funcname", JSONSTR(edata->funcname));
	json_object_object_add(msg, "sqlerrcode", json_object_new_int(edata->sqlerrcode));
	json_object_object_add(msg, "message", JSONSTR(edata->message));
	json_object_object_add(msg, "detail", JSONSTR(edata->detail));
	json_object_object_add(msg, "hint", JSONSTR(edata->hint));
	json_object_object_add(msg, "context", JSONSTR(edata->context));

	return json_object_to_json_string(msg);
}

/*
 * Format the payload as standard syslog message.
 * See: http://tools.ietf.org/html/rfc5424
 */
static const char *format_syslog(ErrorData *edata)
{
	static char msg[MAX_SYSLOG_MESSAGE];
	int			severity;
	int			facility;
	int			pri = 0;
	int			len;
	time_t		now;
	struct tm  *gmt;
	char		ts[32];

	time(&now);
	gmt = gmtime(&now);
	strftime(ts, sizeof(ts), "%F-%dT%H:%M:%SZ", gmt);

	/* What syslog facility to use? */
	facility = 16;	/* local0 */

	/* Map the postgres elevel to syslog severity */
	switch (edata->elevel)
	{
        case DEBUG1:
        case DEBUG2:
        case DEBUG3:
        case DEBUG4:
        case DEBUG5:
            severity = 7; break;
        case LOG:
        case COMMERROR:
        case INFO:
            severity = 6; break;
            break;
        case NOTICE:
            severity = 5; break;
        case WARNING:
            severity = 4; break;
        case ERROR:
            severity = 3; break;
        case FATAL:
            severity = 2; break;
        case PANIC:
            severity = 0; break;
		default:
            severity = 7; break;
	}

	pri = facility * 8 + severity;

	/*
	 * Syslog message format:
	 * PRI VERSION TS HOSTNAME APPNAME PROCID MSGID SDATA MSG
	 */

	/* header */
	len = snprintf(msg, sizeof(msg), "<%d>1 %s %s postgres %d %s ",
		pri, ts, my_hostname, MyProcPid, "-");
	
	/* structured data - skip for now */
	len += snprintf(msg+len, sizeof(msg) - len, "%s ", "-");

	/* message payload */
	len += snprintf(msg+len, sizeof(msg) - len, "%s", edata->message);

	return msg;
}

/*
 * Format the payload as set of netstrings. No fancy stuff, just
 * one field after another: elevel, sqlerrcode, user, database, host,
 * funcname, message, detail, hint, context, debug_query_string
 */
static const char *format_netstr(ErrorData *edata)
{
	static char	msg[MAX_NETSTR_MESSAGE];
	char		intbuf[16];
	char	   *intptr = intbuf;	/* hack to suppress compiler warning */
	int			len = 0;

	snprintf(intbuf, sizeof(intbuf), "%d", edata->elevel);
	len += NETSTR(msg+len, sizeof(msg)-len, intptr);
	snprintf(intbuf, sizeof(intbuf), "%d", edata->sqlerrcode);
	len += NETSTR(msg+len, sizeof(msg)-len, intptr);

	len += NETSTR(msg+len, sizeof(msg)-len, log_username);
	len += NETSTR(msg+len, sizeof(msg)-len, log_database);
	len += NETSTR(msg+len, sizeof(msg)-len, log_hostname);
	len += NETSTR(msg+len, sizeof(msg)-len, edata->funcname);
	len += NETSTR(msg+len, sizeof(msg)-len, edata->message);
	len += NETSTR(msg+len, sizeof(msg)-len, edata->detail);
	len += NETSTR(msg+len, sizeof(msg)-len, edata->hint);
	len += NETSTR(msg+len, sizeof(msg)-len, edata->context);
	len += NETSTR(msg+len, sizeof(msg)-len, debug_query_string);

	return msg;
}

/*
 * Handler for intercepting EmitErrorReport.
 */
static void
emit_log(ErrorData *edata)
{
	const char	*buf = NULL;
	LogTarget   *t;

	/* Call any previous hooks */
	if (prev_emit_log_hook)
		prev_emit_log_hook(edata);

	if (MyProcPort)
	{
		log_database = MyProcPort->database_name;
		log_hostname = MyProcPort->remote_host;
		log_username = MyProcPort->user_name;
	}

	/*
	 * Loop through the log targets, send the message if all 
	 * filter conditions are met.
	 */
	for (t = log_targets; t != NULL; t = t->next)
	{
		/* Skip messages with too low severity */
		if (edata->elevel < t->min_elevel)
			continue;

		/* Skip uninteresting messages */
		if (t->message_filter && !strstr(edata->message, t->message_filter))
			continue;

		buf = t->format_payload(edata);

		if (sendto(t->log_socket, buf, strlen(buf), 0, &t->si_remote, sizeof(t->si_remote)) < 0)
			fprintf(stderr, "pg_logforward: sendto: %s\n", strerror(errno));

	}
}

