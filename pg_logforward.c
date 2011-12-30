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
#include "miscadmin.h"

PG_MODULE_MAGIC;

#define DEFAULT_REMOTE_PORT	23456
#define DEFAULT_REMOTE_IP	"127.0.0.1"

#define JSONSTR(s)	json_object_new_string((s) ? (s) : "")


void _PG_init(void);

static emit_log_hook_type	prev_emit_log_hook = NULL;
static struct				sockaddr_in si_remote;
static int					log_socket = -1;
static int					remote_port = DEFAULT_REMOTE_PORT;
static char				   *remote_ip = DEFAULT_REMOTE_IP;

static void emit_log(ErrorData *edata);


/*
 * Module Load Callback
 */
void
_PG_init(void)
{
	/* Install Hooks */
	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = emit_log;

    /*
     * Define (or redefine) custom GUC variables.
     */

	DefineCustomStringVariable("logforward.remote_host",
			"Remote IP address where logs are forwarded",
			NULL,
			&remote_ip,
#if PG_VERSION_NUM >= 80400
			DEFAULT_REMOTE_IP,	/* bootValue since 8.4 */
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

	DefineCustomIntVariable("logforward.remote_port",
			"Remote port where logs are forwarded",
			NULL,
			&remote_port,
#if PG_VERSION_NUM >= 80400
			DEFAULT_REMOTE_PORT, /* bootValue since 8.4 */
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

	/* Set up the logging socket */
	if ((log_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		fprintf(stderr, "pg_logforward: cannot create socket: %s\n",
				strerror(errno));
	else if (fcntl(log_socket, F_SETFL, O_NONBLOCK) == -1)
		fprintf(stderr, "pg_logforward: cannot set socket nonblocking: %s\n",
				strerror(errno));

	memset((char *) &si_remote, 0, sizeof(si_remote));
	si_remote.sin_family = AF_INET;
	si_remote.sin_port = htons(remote_port);

	if (inet_aton(remote_ip, &si_remote.sin_addr) == 0)
		fprintf(stderr, "pg_logforward: invalid target address: %s\n",
				remote_ip);
	else
		fprintf(stderr, "pg_logforward: forwarding to %s:%d\n",
				remote_ip, remote_port);
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
	const char	*buf;
	json_object	*msg;

	/* Call any previous hooks */
	if (prev_emit_log_hook)
		prev_emit_log_hook(edata);

	/* No working socket, nothing to do */
	if (log_socket < 0)
		return;

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
#if PG_VERSION_NUM >= 80400
	json_object_object_add(msg, "domain", JSONSTR(edata->domain));
	json_object_object_add(msg, "detail_log", JSONSTR(edata->detail_log));
#endif

	buf = json_object_to_json_string(msg);

	if (sendto(log_socket, buf, strlen(buf), 0, &si_remote, sizeof(si_remote)) < 0)
		fprintf(stderr, "pg_logforward: sendto: %s\n", strerror(errno));

	json_object_put(msg);
}

