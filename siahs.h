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
struct siahs_packet {
	uint32_t len;
	char unknown1; /* 0x01 */
	char unknown2; /* 0x01 */
	uint16_t unknown3; /* '0xcfff' big endian */

	/* From this point XOR encoded with either 0xB6 or 0x85 */
	char *device;
	uint16_t prom;
	uint8_t unknown4; /* 0x01 */
	uint8_t unknown5; /* 0x2C */
	uint8_t unknown6; /* 0x01 */
	char *message;
	uint16_t checksum;
};


