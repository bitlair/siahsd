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


static dbi_conn conn;

/*
 * talloc_quoted_string escapes quotes in a string and encapsulates it in quotes.
 * It returns a pointer to talloc'ed memory, the quoted string.
 */
static char *talloc_quoted_string(TALLOC_CTX *mem_ctx, const char *string) {
	/* Allocate twice the string length, to be safe and not having to realloc all the time */
	char *ret = talloc_zero_array(mem_ctx, char, strlen(string) * 2 + 3);
	size_t i, j;

	NO_MEM_RETURN_RV(ret, NULL);

	ret[0] = '\'';

	for (i = 0, j = 1; i < strlen(string); i++, j++) {
		if (string[i] == '\'' || string[i] == '\\') {
			ret[j] = '\'';
			ret[++j] = string[i];
		} else {
			ret[j] = string[i];
		}
	}
	ret[j] = '\'';
	ret[++j]  = '\0';

	return ret;
}

STATUS proper_dbi_queryf(dbi_conn dbconn, const char *query_fmt, ...) {
	va_list ap;
	int conn_res;
	dbi_result dbi_res;
	TALLOC_CTX *local_ctx;
	char *query;

	conn_res = dbi_conn_connect(dbconn);
	if (conn_res != DBI_ERROR_NONE) {
		const char *errmsg;
		int err_res = dbi_conn_error(dbconn, &errmsg);

		if (err_res == DBI_ERROR_NONE) {
			DEBUG(0, "Strange situation: There was an error, but error buffer is empty");
		} else {
			DEBUG(0, "Database error %d/%d while connecting: %s", conn_res, err_res, errmsg);
		}
		return ST_DATABASE_FAILURE;
	}

	local_ctx = talloc_init(NULL);

	va_start(ap, query_fmt);
	query = talloc_vasprintf(local_ctx, query_fmt, ap);
	DEBUG(5, "Executing query %s.", query);
	va_end(ap);

	dbi_res = dbi_conn_query(dbconn, query);
	if (dbi_res == NULL) {
		const char *errmsg;
		int err_res = dbi_conn_error(dbconn, &errmsg);

		if (err_res == DBI_ERROR_NONE) {
			DEBUG(0, "Strange situation: There was an error, but error buffer is empty");
		} else {
			DEBUG(0, "Database error %d when querying: %s", err_res, errmsg);
		}
		talloc_free(local_ctx);
		return ST_DATABASE_FAILURE;
	}

	//dbi_conn_close(dbconn);

	talloc_free(local_ctx);
	return ST_OK;
}

STATUS log_event_to_database(TALLOC_CTX *mem_ctx, const char *prom, const char *code, const char *description) {
	char *quoted_prom;
	char *quoted_code;
	char *quoted_long_code;
	char *quoted_description;
	
	quoted_prom = talloc_quoted_string(mem_ctx, prom);
	NO_MEM_RETURN(quoted_prom);
	quoted_code = talloc_quoted_string(mem_ctx, code);
	NO_MEM_RETURN(quoted_code);
	quoted_long_code = talloc_quoted_string(mem_ctx, sia_code_str(code));
	NO_MEM_RETURN(quoted_long_code);
	quoted_description = talloc_quoted_string(mem_ctx, description);
	NO_MEM_RETURN(quoted_description);

	DEBUG(3, "Storing event: %s %s %s -- %s: %s\n", prom, code, description, sia_code_str(code), sia_code_desc(code));
	
	proper_dbi_queryf(conn, "INSERT INTO events (timestamp, prom, code, long_code, description) VALUES (NOW(), %s, %s, %s, %s)\n",
		 quoted_prom, quoted_code, quoted_long_code, quoted_description);

	talloc_free(quoted_prom);
	talloc_free(quoted_code);
	talloc_free(quoted_long_code);
	talloc_free(quoted_description);

	return ST_OK;
}



STATUS database_init(void)
{
	configuration *conf = get_modifiable_conf();
	GError *error = NULL;
	dbi_inst dbi_instance = 0;

	conf->database_host = g_key_file_get_string(conf->keyfile, "database",
												"host", &error);
	if (error) {
		fprintf(stderr, "No database host supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_name = g_key_file_get_string(conf->keyfile, "database",
												"name", &error);
	if (error) {
		fprintf(stderr, "No database name supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_driver = g_key_file_get_string(conf->keyfile, "database",
												  "driver", &error);
	if (error) {
		fprintf(stderr, "No database driver supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_username = g_key_file_get_string(conf->keyfile, "database",
													"username", &error);
	if (error) {
		fprintf(stderr, "No database username supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_password = g_key_file_get_string(conf->keyfile, "database",
													"password", &error);
	if (error) {
		fprintf(stderr, "No database password supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}

	conf->event_handlers = talloc_realloc(conf, conf->event_handlers, event_function, conf->event_handler_cnt+1);
	conf->event_handlers[conf->event_handler_cnt] = log_event_to_database;
	conf->event_handler_cnt++;

	DEBUG(1, "Setting properties to %s database %s at %s as user %s", conf->database_driver, 
		conf->database_name, conf->database_host, conf->database_username);

	dbi_initialize_r(NULL, &dbi_instance);
	conn = dbi_conn_new_r(conf->database_driver, &dbi_instance);
	dbi_conn_set_option(conn, "host", conf->database_host);
	dbi_conn_set_option(conn, "username", conf->database_username);
	dbi_conn_set_option(conn, "password", conf->database_password);
	dbi_conn_set_option(conn, "dbname", conf->database_name);
	dbi_conn_set_option(conn, "encoding", "UTF-8");

	return ST_OK;
}

