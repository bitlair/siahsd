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
} configuration;


configuration *get_conf(void);
const char *get_process_name(void);

STATUS set_process_name(const char *name);
STATUS read_configuration_file(TALLOC_CTX *mem_ctx);
