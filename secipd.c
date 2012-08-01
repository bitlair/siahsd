/*
   Vebon Sec-IP Alarm Monitoring Service
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
#include "ndr_secip.h"

uint16_t calculate_crc (char *ptr, uint16_t count)
{
	#define CRC16_SEED 0x1021
	uint16_t crc;
	uint8_t i;
	crc = 0;

	while (count-- > 0) {
		crc = crc ^ ((uint16_t) *ptr++ << 8);
		for (i = 0; i < 8; i++) {
			if (crc & 0x8000) {
				crc = crc << 1 ^ CRC16_SEED;
			} else {
				crc = crc << 1;
			}
		}
	}
	return crc;
}


int main (int argc, char **argv) {
	int sock, n;
	socklen_t fromlen;
	struct sockaddr_in server;
	struct sockaddr_in from;
	TALLOC_CTX *mem_ctx;
	dbi_conn conn;
	STATUS rv;
	FILE *pidfile;
	pid_t pid;
	configuration *conf;

	set_process_name(argv[0]);

	/* Initialize a memory context */
	mem_ctx = talloc_init("secipd");


	/* Read the configuration file */
	rv = read_configuration_file(mem_ctx);
	if (rv != ST_OK)
		return rv;

	conf = get_conf();

	/* Daemonize if we're not supposed to run in foreground mode */
	if (!conf->foreground) {
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		if ((pid = fork())) {
			/* Write PID file */
			pidfile = fopen(conf->pid_file, "w");
			if (pidfile < 0)
				return ST_LOG_ERR;

			n = fprintf(pidfile, "%d\n", pid);
			fclose(pidfile);
			return ST_OK;
		}
	}

	/*
	 * Open up a UDP socket the configured port
	 */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		DEBUG(0, "Could not create socket in server");
		return ST_SOCKET_FAILURE;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(conf->secip_port);
	server.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		DEBUG(0, "Could not bind to socket during startup (socket in use?)!");
		return ST_BIND_FAILURE;
	}


	DEBUG(0, "Started %s and waiting for SecIP packets on port %d", 
	         get_process_name(), conf->secip_port);

	/* Open a connection to the database */
	rv = connect_to_database(&conn);
	if (rv != ST_OK)
		return rv;
	
	/*
	 * Wait for packets
	 */

	fromlen = sizeof(struct sockaddr_in);
	while (1) {
		uint16_t src_port;
		struct secip_packet *pkt;
		char buf[1024]; /* Purposefully static length */
		enum ndr_err_code ndr_err;
		DATA_BLOB data;

		pkt = talloc(mem_ctx, struct secip_packet);

		n = recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &from, &fromlen);
		if (n < 0) {
			DEBUG( 0, "Error when storing packet in buffer!");
			continue;
		} else if (n == sizeof(buf)) {
			DEBUG(0, "Maximum packet size exceeded!");
			continue;
		}
		src_port = ntohs(from.sin_port);

		/* Copy to data blob */
		data.length = n;
		data.data = talloc_memdup(pkt, buf, n);
		
		/* Parse the header */
		ndr_err = ndr_pull_struct_blob_all(&data, pkt, pkt, (ndr_pull_flags_fn_t)ndr_pull_secip_packet);

		if (ndr_err != NDR_ERR_SUCCESS) {
			DEBUG(0, "Could not parse this packet");
		}
		printf("%s\n", ndr_print_struct_string(pkt,(ndr_print_fn_t)ndr_print_secip_packet, "packet", pkt));

		DEBUG(0, "%x %x %x %x", pkt->connection_id, pkt->message_id, pkt->sequence_number, pkt->crc);
		if (pkt->message_id == SECIP_MSG_ATE_ENC && pkt->msg.ate_enc.session_id == 0x0000) {
			send_ppk_com(sock, from, pkt);
		}
		DEBUG(3, "Received packet with len %d from %u", n, src_port);
	}
}
