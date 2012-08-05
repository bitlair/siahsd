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
struct rsa_public_key *public_key = NULL;
struct rsa_private_key *private_key = NULL;

const configuration *get_conf(void) {
	return conf;
}

const char *get_process_name(void) {
	return process_name;
}

STATUS set_process_name(const char *name) {
	process_name = name;
	return ST_OK;
}

STATUS get_rsa_keys(struct rsa_public_key **pub, struct rsa_private_key **priv) {
	if (pub == NULL || priv == NULL) {
		return ST_NO_SUCH_OBJECT;
	}
	*pub = public_key;
	*priv = private_key;
	return ST_OK;
}
STATUS set_rsa_keys(struct rsa_public_key *pub, struct rsa_private_key *priv) {
	public_key = pub;
	private_key = priv;

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
	conf->jsonbot_address = g_key_file_get_string(keyfile, "jsonbot", "address", &error);
	if (error) {
		fprintf(stderr, "No jsonbot address supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->jsonbot_port = g_key_file_get_integer(keyfile, "jsonbot", "port", &error);
	if (error) {
		fprintf(stderr, "No jsonbot port supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->jsonbot_aeskey = g_key_file_get_string(keyfile, "jsonbot", "aes key", &error);
	if (error) {
		fprintf(stderr, "No jsonbot aes key supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->jsonbot_password = g_key_file_get_string(keyfile, "jsonbot", "password", &error);
	if (error) {
		fprintf(stderr, "No jsonbot password supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->jsonbot_privmsg_to = g_key_file_get_string(keyfile, "jsonbot", "privmsg to", &error);
	if (error) {
		fprintf(stderr, "No jsonbot privsmg to supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->foreground = g_key_file_get_boolean(keyfile, "siahsd", "foreground", &error);
	if (error) {
		conf->foreground = false;
	}
	/* Optional parameters are protocol-specific */
	conf->siahs_port = g_key_file_get_integer(keyfile, "siahs", "port", &error);
	conf->secip_port = g_key_file_get_integer(keyfile, "secip", "port", &error);
	conf->rsa_key_file = g_key_file_get_string(keyfile, "secip", "rsa key file", &error);


	return ST_OK;
}

