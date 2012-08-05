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

typedef struct {
	char *database_host;
	char *database_username;
	char *database_password;
	char *database_name;
	char *database_driver;
	gint siahs_port;
	char *log_file;
	gint log_level;
	gboolean foreground;
	char *pid_file;
	gint secip_port;
	char *rsa_key_file;
	char *jsonbot_address;
	gint jsonbot_port;
	char *jsonbot_aeskey;
	char *jsonbot_password;
	char *jsonbot_privmsg_to;
} configuration;


const configuration *get_conf(void);
STATUS get_rsa_keys(struct rsa_public_key **pub, struct rsa_private_key **priv);
STATUS set_rsa_keys(struct rsa_public_key *pub, struct rsa_private_key *priv);

const char *get_process_name(void);
STATUS set_process_name(const char *name);
STATUS read_configuration_file(TALLOC_CTX *mem_ctx);
