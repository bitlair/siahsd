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

#define DEBUG(level, ...) debug(level, __location__, __func__, __VA_ARGS__)


typedef enum {
	ST_OK = 0,
	ST_GENERAL_FAILURE = 1,
	ST_NO_SUCH_OBJECT = 2,
	ST_READ_ERROR = 3,
	ST_WRITE_ERROR = 4,
	ST_PARSE_ERROR = 5,
	ST_LOG_ERR = 117,
	ST_DATABASE_FAILURE = 118,
	ST_BIND_FAILURE = 119,
	ST_SOCKET_FAILURE = 120,
	ST_CONFIGURATION_ERROR = 121,
	ST_ASSERTION_FAILED = 122,
	ST_NOT_IMPLEMENTED = 123,
	ST_OUT_OF_MEMORY = 124,
} STATUS;

#define NO_MEM_RETURN(ptr) {if (ptr == NULL) { DEBUG(0, "Out of memory"); return ST_OUT_OF_MEMORY; }}
#define NO_MEM_RETURN_RV(ptr, rv) {if (ptr == NULL) { DEBUG(0, "Out of memory"); return rv; }}


STATUS debug(int loglevel, const char *location, const char *function, ...);
