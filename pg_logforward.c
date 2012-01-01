#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <json/json.h>

#include "postgres.h"
#include "tcop/tcopprot.h"
#include "libpq/libpq.h"
#include "utils/memutils.h"
#include "miscadmin.h"

PG_MODULE_MAGIC;

#define JSONSTR(s)	json_object_new_string((s) ? (s) : "")

typedef struct LogTarget {
	struct LogTarget   *next;
	const char		   *name;
	char			   *remote_ip;
	int					remote_port;
	int					log_socket;
	struct sockaddr_in	si_remote;

	/* Log filtering */
	int					min_elevel;
	char			   *message_filter;
} LogTarget;


void _PG_init(void);
static void emit_log(ErrorData *edata);
void defineStringVariable(const char *name, const char *short_desc, char **value_addr);
void defineIntVariable(const char *name, const char *short_desc, int *value_addr);


static emit_log_hook_type	prev_emit_log_hook = NULL;
static LogTarget		   *log_targets = NULL;
static char				   *log_target_names = "";


/* Convinience wrapper for DefineCustomStringVariable */
void defineStringVariable(	const char *name,
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
void defineIntVariable(	const char *name,
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

		fprintf(stderr, "setting up target %s\n", tgname);

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

		fprintf(stderr, "pg_logforward: forwarding to target %s: %s:%d\n",
				tgname, target->remote_ip, target->remote_port);

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
 * Handler for intercepting EmitErrorReport.
 */
static void
emit_log(ErrorData *edata)
{
	const char	*log_database = MyProcPort ? MyProcPort->database_name : "";
	const char	*log_hostname = MyProcPort ? MyProcPort->remote_host : "";
	const char	*log_username = MyProcPort ? MyProcPort->user_name : "";
	const char	*buf = NULL;
	json_object	*msg = NULL;
	LogTarget   *t;

	/* Call any previous hooks */
	if (prev_emit_log_hook)
		prev_emit_log_hook(edata);

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

		if (!msg)
		{
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

			buf = json_object_to_json_string(msg);
		}

		if (sendto(t->log_socket, buf, strlen(buf), 0, &t->si_remote, sizeof(t->si_remote)) < 0)
			fprintf(stderr, "pg_logforward: sendto: %s\n", strerror(errno));
	}

	if (msg)
		json_object_put(msg);
}

