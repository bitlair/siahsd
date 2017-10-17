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

#define CONFIGFILE "/etc/siahsd.conf"

typedef STATUS (*event_function)(TALLOC_CTX *mem_ctx, const char *prom, const char *code, const char *description);

typedef struct {
	/* Global configuration */
	char *log_file;
	gint log_level;
	gboolean foreground;
	char *pid_file; /* FIXME Apparently the same for siahs and secip.. for now */

	/* Alphatronics SIA-HS configuration */
	gint siahs_port;

	/* Vebon SecIP configuration */
	gint secip_port;
	char *rsa_key_file;

	/* Database client configuration */
	char *database_host;
	char *database_username;
	char *database_password;
	char *database_name;
	char *database_driver;

	/* JSONbot client configuration */
	char *jsonbot_address;
	gint jsonbot_port;
	char *jsonbot_aeskey;
	char *jsonbot_password;
	char *jsonbot_privmsg_to;

	char *hook_script_path;

	/* Global configuration based state */
	GKeyFile *keyfile;
	uint8_t event_handler_cnt;
	event_function *event_handlers;
	struct rsa_public_key *public_key;
	struct rsa_private_key *private_key;
} configuration;


const configuration *get_conf(void);
configuration *get_modifiable_conf(void);

STATUS read_rsa_keys(void);

const char *get_process_name(void);
STATUS set_process_name(const char *name);
STATUS read_configuration_file(TALLOC_CTX *mem_ctx);
