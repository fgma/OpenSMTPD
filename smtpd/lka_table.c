/*
 * Copyright (c) 2019 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd.h"
#include "log.h"

#define	PROTOCOL_VERSION	"0.1"

static void
table_write(struct table *t, struct timeval *tv, const char *event, const char *format, ...)
{
	va_list		ap;
	uint64_t	token = generate_uid();

	va_start(ap, format);
	if (io_printf(lka_proc_get_io(t->t_proc),
		"table|%s|%lld.%06ld|%016"PRIx64"|%s|%s%s",
		PROTOCOL_VERSION, tv->tv_sec, tv->tv_usec, token,
		event, t->t_name, format[0] != '\n' ? "|" : "") == -1 ||
	    io_vprintf(lka_proc_get_io(t->t_proc), format, ap) == -1)
		fatalx("failed to write to processor");
	va_end(ap);
}

int
lka_table_open(struct table *t, struct timeval *tv)
{
	table_write(t, tv, "open", "\n");
}

int
lka_table_update(struct table *t, struct timeval *tv)
{
	table_write(t, tv, "update", "\n");
}

int
lka_table_close(struct table *t, struct timeval *tv)
{
	table_write(t, tv, "close", "\n");
}

int
lka_table_lookup(struct table *t, struct timeval *tv, enum table_service s, const char *k, char **dst)
{
	const char *service;

	switch (s) {
	case K_ALIAS:
		service = "alias";
		break;
	case K_DOMAIN:
		service = "domain";
		break;
	case K_CREDENTIALS:
		service = "credentials";
		break;
	case K_NETADDR:
		service = "netaddr";
		break;
	case K_USERINFO:
		service = "userinfo";
		break;
	case K_SOURCE:
		service = "source";
		break;
	case K_MAILADDR:
		service = "mailaddr";
		break;
	case K_ADDRNAME:
		service = "addrname";
		break;
	case K_MAILADDRMAP:
		service = "mailaddrmap";
		break;
	case K_RELAYHOST:
		service = "relayhost";
		break;
	case K_STRING:
		service = "string";
		break;
	case K_REGEX:
		service = "regex";
		break;
	case K_NONE:
		service = "none";
		break;
	}

	table_write(t, tv, "lookup", "%s|%s\n", service, k);
	if (dst)
		*dst = xstrdup("test");
	return 1;
}

int
lka_table_fetch(struct table *t, struct timeval *tv, enum table_service s, char **dst)
{
	const char *service;

	switch (s) {
	case K_ALIAS:
		service = "alias";
		break;
	case K_DOMAIN:
		service = "domain";
		break;
	case K_CREDENTIALS:
		service = "credentials";
		break;
	case K_NETADDR:
		service = "netaddr";
		break;
	case K_USERINFO:
		service = "userinfo";
		break;
	case K_SOURCE:
		service = "source";
		break;
	case K_MAILADDR:
		service = "mailaddr";
		break;
	case K_ADDRNAME:
		service = "addrname";
		break;
	case K_MAILADDRMAP:
		service = "mailaddrmap";
		break;
	case K_RELAYHOST:
		service = "relayhost";
		break;
	case K_STRING:
		service = "string";
		break;
	case K_REGEX:
		service = "regex";
		break;
	case K_NONE:
		service = "none";
		break;
	}

	table_write(t, tv, "fetch", "%s\n", service);
	if (dst)
		*dst = xstrdup("test");
	return 1;
}

void
lka_table_proc(const char *name, const char *line)
{
	char buffer[LINE_MAX];
	char *ep, *sp, *result, *value;
	uint64_t reqid;

	sp = buffer;
	if (strlcpy(buffer, line + 13, sizeof(buffer)) >= sizeof(buffer))
		fatalx("Invalid table-result: line too long: %s", line);

	reqid = strtoull(sp, &ep, 16);
	if (ep[0] != '|' || errno != 0)
		fatalx("Invalid table-result: invalid reqid: %s", line);
	sp = ep + 1;

	result = sp;
	if ((ep = strchr(sp, '|')) == NULL)
		fatalx("Invalid table-result: invalid result: %s", line);
	*ep = '\0';
	sp = ep + 1;

	if (strcmp(result, "ok") != 0 &&
	    strcmp(result, "tempfail") != 0 &&
	    strcmp(result, "permfail") != 0)
		fatalx("Invalid table-result: invalid result: %s", value);

	value = sp;
	log_debug("####%s: [%s]", name, result);
	log_debug("####%s: [%s]", name, value);

//	lka_report_filter_report(reqid, name, 0, direction, &tv, sp);
}
