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


/*
 * talloc_quoted_string escapes quotes in a string and encapsulates it in quotes.
 * It returns a pointer to talloc'ed memory, the quoted string.
 */
static char *talloc_quoted_string(TALLOC_CTX *mem_ctx, const char *string) {
	/* Allocate twice the string length, to be safe and not having to realloc all the time */
	char *ret = talloc_zero_array(mem_ctx, char, strlen(string) * 2 + 1);
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

STATUS log_event_to_database(TALLOC_CTX *mem_ctx, dbi_conn conn, const char *prom, const char *code, const char *description) {
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

	dbi_conn_queryf(conn, "INSERT INTO events (timestamp, prom, code, long_code, description) VALUES (NOW(), %s, %s, %s, %s)\n",
		 quoted_prom, quoted_code, quoted_long_code, quoted_description);

	talloc_free(quoted_prom);
	talloc_free(quoted_code);
	talloc_free(quoted_long_code);
	talloc_free(quoted_description);

	return ST_OK;
}

STATUS connect_to_database(dbi_conn *conn)
{
	const configuration *conf = get_conf();

	DEBUG(1, "Connecting to %s database %s at %s as user %s", conf->database_driver, 
		conf->database_name, conf->database_host, conf->database_username);

	dbi_initialize(NULL);
	*conn = dbi_conn_new(conf->database_driver);
	dbi_conn_set_option(*conn, "host", conf->database_host);
	dbi_conn_set_option(*conn, "username", conf->database_username);
	dbi_conn_set_option(*conn, "password", conf->database_password);
	dbi_conn_set_option(*conn, "dbname", conf->database_name);
	dbi_conn_set_option(*conn, "encoding", "UTF-8");

	if (dbi_conn_connect(*conn) < 0) {
		DEBUG(0, "Could not connect to the database");
		return ST_DATABASE_FAILURE;
	} 

	return ST_OK;
}

