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

/* TODO:
 * - Have each event protocol definition get its own configuration directives
 */

#include "includes.h"

/* My global state */
configuration *conf = NULL;
const char *process_name = NULL;
struct rsa_public_key *public_key = NULL;
struct rsa_private_key *private_key = NULL;

configuration *get_modifiable_conf(void) {
	return conf;
}

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

STATUS read_rsa_keys(void) {
	int res;
	FILE *file;
	uint8_t buf[1024];
	struct rsa_private_key *priv;
	struct rsa_public_key *pub;
	uint8_t *buffer = NULL;
	size_t n, size=0;

	priv = talloc(conf, struct rsa_private_key);
	pub = talloc(conf, struct rsa_public_key);

	rsa_public_key_init (pub);
	rsa_private_key_init (priv);

	file = fopen(conf->rsa_key_file, "r");
	if (file == NULL) {
		DEBUG(0, "Can't open configured rsa key file: %s", conf->rsa_key_file);
		exit(ST_CONFIGURATION_ERROR);
	}

	while (1) {
		n = fread(&buf, 1, 1024, file);
		buffer = talloc_realloc(conf, buffer, uint8_t, size + n);
		memcpy(buffer + size, buf, n);
		size += n;
		if (n < 1024)
			break;
	}

	fclose(file);

	res = rsa_keypair_from_sexp(pub, priv, 0, size, buffer);
	if (!res) {
		DEBUG(0, "Error reading the RSA keypair from the SEXP file");
	}

	conf->public_key = pub;
	conf->private_key = priv;

	return res;
}

STATUS read_configuration_file(TALLOC_CTX *mem_ctx)
{
	GError *error = NULL;
	char *buf, *ptr;

	conf = talloc(mem_ctx, configuration);
	NO_MEM_RETURN(conf);

 	conf->keyfile = g_key_file_new ();

	if (!g_key_file_load_from_file (conf->keyfile, CONFIGFILE, 0, &error)) {
		g_error (error->message);
        g_error_free(error);
		return ST_CONFIGURATION_ERROR;
	}

	buf = g_key_file_get_string(conf->keyfile, "siahsd", "event handlers", &error);
	if (error) {
		fprintf(stderr, "No event handler supplied in the configuration.\n");
        g_error_free(error);
		return ST_CONFIGURATION_ERROR;
	}

	conf->log_file = g_key_file_get_string(conf->keyfile, "siahsd", "log file", &error);
	if (error) {
		fprintf(stderr, "No log file supplied in the configuration.\n");
        g_error_free(error);
		return ST_CONFIGURATION_ERROR;
	}
	conf->log_level = g_key_file_get_integer(conf->keyfile, "siahsd", "log level", &error);
	if (error) {
		fprintf(stderr, "No log level supplied in the configuration.\n");
        g_error_free(error);
		return ST_CONFIGURATION_ERROR;
	}
	conf->pid_file = g_key_file_get_string(conf->keyfile, "siahsd", "pid file", &error);
	if (error) {
		fprintf(stderr, "No pid file supplied in the configuration.\n");
        g_error_free(error);
		return ST_CONFIGURATION_ERROR;
	}

	conf->foreground = g_key_file_get_boolean(conf->keyfile, "siahsd", "foreground", &error);
	if (error) {
		conf->foreground = false;
        g_error_free(error);
        error = NULL;
	}

	/* Initialize the required event handler backends */
	ptr = strtok(buf, " ");
	if (ptr != NULL) {
		do {
			if (strcmp(ptr, "database") == 0) {
				database_init();
			} else if (strcmp(ptr, "jsonbot") == 0) {
				jsonbot_init();
			}
		} while((ptr = strtok(NULL, " ")) != NULL);
	}

	/* Optional parameters are protocol-specific */
	/* FIXME Warn the user when these aren't configured */
	conf->siahs_port = g_key_file_get_integer(conf->keyfile, "siahs", "port", &error);
    if (error) {
        g_error_free(error);
        error = NULL;
    }
	conf->secip_port = g_key_file_get_integer(conf->keyfile, "secip", "port", &error);
    if (error) {
        g_error_free(error);
        error = NULL;
    }
	conf->rsa_key_file = g_key_file_get_string(conf->keyfile, "secip", "rsa key file", &error);
    if (error) {
        g_error_free(error);
        error = NULL;
    }

	return ST_OK;
}

