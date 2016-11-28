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

STATUS debug(int loglevel, const char *location, const char *function, ...)
{
	va_list ap;
	static char timebuf[100]; /* Static because this should not be reallocated 
	                             in case of out of memory errors */
	time_t rawtime;
	struct tm *timeinfo;
	size_t s;
	FILE *logfile;
	const configuration *conf = get_conf();

	if (loglevel > conf->log_level) {
		return ST_OK;
	}

	logfile = fopen(conf->log_file, "a");
	if (logfile == NULL) {
		if (conf->foreground) {
			fprintf(stderr, "Error opening log file: %s\n", strerror(errno));
		}
		return ST_GENERAL_FAILURE;
	}

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	
	s = strftime(timebuf, sizeof(timebuf), "%c", timeinfo);
	if (s == 0) {
		const char *text = "Failed to get proper strftime formatted date\n";
		if (conf->foreground) {
			fprintf(stderr, "%s", text);
		}
		fprintf(logfile, "%s", text);
		fclose(logfile);
		return ST_GENERAL_FAILURE;
	}

	fprintf(logfile, "%s: %s(%d): Log level %d, at %s in function %s():\n",
	                 timebuf, get_process_name(), getpid(), loglevel, location, function);
	if (conf->foreground)
		fprintf(stderr, "%s: %s(%d): Log level %d, at %s in function %s():\n",
		                timebuf, get_process_name(), getpid(), loglevel, location, function);

	va_start(ap, function);
	vfprintf(logfile, va_arg(ap, char *), ap);
	va_end(ap);
	fputc('\n', logfile);

	if (conf->foreground) {
		va_start(ap, function);
		vfprintf(stderr, va_arg(ap, char *), ap);
		va_end(ap);
		fputc('\n', stderr);
	}

	fclose(logfile);

	return ST_OK;
}

