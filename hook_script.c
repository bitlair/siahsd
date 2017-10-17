/*
   SIA-HS Alarm Monitoring Service
   Copyright (C) Wilco Baan Hofman <wilco@baanhofman.nl> 2013

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#define _XOPEN_SOURCE
#include "includes.h"
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

static void child_handler(int sig) {
	pid_t pid;
	int status;
	/* EXTERMINATE! EXTERMINATE! */
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

STATUS script_update(TALLOC_CTX *mem_ctx, const char *prom, const char *code, const char *description) {
	DEBUG(6, "Got event for script hook: %s %s: %s -- %s: %s\n", prom, code, description, sia_code_str(code), sia_code_desc(code));

	const configuration *conf = get_conf();
	DEBUG(4, "About to execute %s", conf->hook_script_path);
	if (!fork()) {
		execl(
			conf->hook_script_path,
			conf->hook_script_path,
			prom,
			code,
			description,
			sia_code_str(code),
			sia_code_desc(code),
			(char *)NULL
		);
		exit(0);
	}
	return ST_OK;
}

STATUS script_init(void) {
	/* Establish SIGCHLD handler. */
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);

	GError *error = NULL;
	configuration *conf = get_modifiable_conf();
	conf->hook_script_path = g_key_file_get_string(conf->keyfile, "script", "path", &error);
	if (error) {
		DEBUG(2, "Disabling script hook because no path is set");
		return ST_OK;
	}
	DEBUG(3, "Script hook enabled");

	conf->event_handlers = talloc_realloc(conf, conf->event_handlers, event_function, conf->event_handler_cnt+1);
	conf->event_handlers[conf->event_handler_cnt] = script_update;
	conf->event_handler_cnt++;

	return ST_OK;
}
