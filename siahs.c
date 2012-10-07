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
 * parse_message parses the string portion of the SIA-HS message
 * and writes the event to the database.
 * It returns nothing.
 */
STATUS parse_siahs_message(TALLOC_CTX *mem_ctx, const char *pkt_prom, const char *orig_message) {
	char *message = talloc_strdup(mem_ctx, orig_message);
	char *ptr = message;
	char *prom = ptr;
	char *code;
	const configuration *conf = get_conf();
	uint8_t i;

	NO_MEM_RETURN(message);

	/* Grab the first part, the prom */
	while (*ptr != '\0' && *ptr != 'N') {
		ptr++;
	}
	*ptr++ = '\0';

	/* Grab the second part, SIA code */
	code = ptr;
	while (*ptr != '\0' && *ptr != ',') {
		ptr++;
	}
	if (*ptr != '\0') *ptr++ = '\0';

	/* The remaining ptr contains the human readable description string */

	if (strcmp(pkt_prom, prom) != 0) {
		return ST_ASSERTION_FAILED;
	}

	/* Ignore alive! messages */
	if (strcmp(code, "alive!") == 0) {
		DEBUG(2, "Got keepalive packet from prom %s", prom);
		/* FIXME We must update some keepalive status somewhere to generate offline messages */
		return ST_OK;
	}

	/* Dispatch all configured event handlers */
	for (i = 0; conf->event_handlers[i] != NULL; i++) {
		conf->event_handlers[i](message, prom, code, ptr);
	}

	talloc_free(message);

	return ST_OK;
}


