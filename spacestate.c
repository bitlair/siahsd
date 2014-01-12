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
#include "includes.h"
#include "database.h"


static dbi_conn conn;

STATUS spacestate_update(TALLOC_CTX *mem_ctx, const char *prom, const char *code, const char *description) {
	bool must_close = 0;
	bool must_open = 0;
	STATUS result = ST_OK;

	DEBUG(6, "Got event for spacestate: %s %s %s -- %s: %s\n", prom, code, description, sia_code_str(code), sia_code_desc(code));


	if (strncmp(code, "CL", 2) == 0 ||
			strncmp(code, "CA", 2) == 0 ||
			strncmp(code, "CF", 2) == 0 ||
			strncmp(code, "CJ", 2) == 0 ||
			strncmp(code, "CK", 2) == 0 ||
			strncmp(code, "CQ", 2) == 0 ||
			strncmp(code, "CS", 2) == 0) {
		must_close = 1;
	}

	if (strncmp(code, "OP", 2) == 0 ||
			strncmp(code, "OA", 2) == 0 ||
			strncmp(code, "OJ", 2) == 0 ||
			strncmp(code, "OK", 2) == 0 ||
			strncmp(code, "OQ", 2) == 0 ||
			strncmp(code, "OS", 2) == 0) {
		must_open = 1;
	}

	if (must_open) {
		DEBUG(3, "Alarm disarmed. Updating space state override.");
		result = proper_dbi_queryf(conn, "UPDATE space_state set override=0, override_state='open';");
	} else if (must_close) {
		DEBUG(3, "Alarm armed. Updating space state override.");
		result = proper_dbi_queryf(conn, "UPDATE space_state set override=1, override_state='closed';");
	}

	if (result != ST_OK) {
		return result;
	}

	return ST_OK;
}



STATUS spacestate_init(void)
{
	configuration *conf = get_modifiable_conf();
	GError *error = NULL;

	conf->spacestate_host = g_key_file_get_string(conf->keyfile, "spacestate",
	                                              "host", &error);
	if (error) {
		fprintf(stderr, "No spacestate host supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->spacestate_name = g_key_file_get_string(conf->keyfile, "spacestate",
	                                              "name", &error);
	if (error) {
		fprintf(stderr, "No spacestate name supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->spacestate_driver = g_key_file_get_string(conf->keyfile, "spacestate",
	                                                "driver", &error);
	if (error) {
		fprintf(stderr, "No spacestate driver supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->spacestate_username = g_key_file_get_string(conf->keyfile, "spacestate",
	                                                  "username", &error);
	if (error) {
		fprintf(stderr, "No spacestate username supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->spacestate_password = g_key_file_get_string(conf->keyfile, "spacestate",
	                                                  "password", &error);
	if (error) {
		fprintf(stderr, "No spacestate password supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}

	conf->event_handlers = talloc_realloc(conf, conf->event_handlers, event_function, conf->event_handler_cnt+1);
	conf->event_handlers[conf->event_handler_cnt] = spacestate_update;
	conf->event_handler_cnt++;

	DEBUG(1, "Connecting to %s space state database %s at %s as user %s", conf->spacestate_driver,
		conf->spacestate_name, conf->spacestate_host, conf->spacestate_username);

	dbi_initialize(NULL);
	conn = dbi_conn_new(conf->spacestate_driver);
	dbi_conn_set_option(conn, "host", conf->spacestate_host);
	dbi_conn_set_option(conn, "username", conf->spacestate_username);
	dbi_conn_set_option(conn, "password", conf->spacestate_password);
	dbi_conn_set_option(conn, "dbname", conf->spacestate_name);
	dbi_conn_set_option(conn, "encoding", "UTF-8");

	if (dbi_conn_connect(conn) < 0) {
		DEBUG(0, "Could not connect to the space state database");
		return ST_DATABASE_FAILURE;
	}

	return ST_OK;
}

