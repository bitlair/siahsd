/*
   SIA-HS Alarm Monitoring Service
   Copyright (C) Wilco Baan Hofman <wilco@baanhofman.nl> 2012

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

/* My global state */
configuration *conf = NULL;
const char *process_name = NULL;


configuration *get_conf(void) {
	return conf;
}

const char *get_process_name(void) {
	return process_name;
}

STATUS set_process_name(const char *name) {
	process_name = name;
	return ST_OK;
}

STATUS read_configuration_file(TALLOC_CTX *mem_ctx)
{
	GError *error = NULL;
	GKeyFile *keyfile = g_key_file_new ();

	if (!g_key_file_load_from_file (keyfile, CONFIGFILE, 0, &error)) {
		g_error (error->message);
		return ST_CONFIGURATION_ERROR;
	}

	conf = talloc(mem_ctx, configuration);
	NO_MEM_RETURN(conf);

	conf->database_host = g_key_file_get_string(keyfile, "database",
                                                  "host", &error);
	if (error) {
		fprintf(stderr, "No database host supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_name = g_key_file_get_string(keyfile, "database",
                                                  "name", &error);
	if (error) {
		fprintf(stderr, "No database name supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_driver = g_key_file_get_string(keyfile, "database",
                                                  "driver", &error);
	if (error) {
		fprintf(stderr, "No database driver supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_username = g_key_file_get_string(keyfile, "database",
                                                  "username", &error);
	if (error) {
		fprintf(stderr, "No database username supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_password = g_key_file_get_string(keyfile, "database",
                                                  "password", &error);
	if (error) {
		fprintf(stderr, "No database password supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}

	conf->siahs_port = g_key_file_get_integer(keyfile, "siahs", "port", &error);
	if (error) {
		fprintf(stderr, "No SIA-HS port supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->log_file = g_key_file_get_string(keyfile, "siahsd", "log file", &error);
	if (error) {
		fprintf(stderr, "No log file supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->log_level = g_key_file_get_integer(keyfile, "siahsd", "log level", &error);
	if (error) {
		fprintf(stderr, "No log level supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->pid_file = g_key_file_get_string(keyfile, "siahsd", "pid file", &error);
	if (error) {
		fprintf(stderr, "No pid file supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->foreground = g_key_file_get_boolean(keyfile, "siahsd", "foreground", &error);
	if (error) {
		conf->foreground = false;
	}
	conf->secip_port = g_key_file_get_integer(keyfile, "secip", "port", &error);
	if (error) {
		fprintf(stderr, "No SecIP port supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}

	return ST_OK;
}

