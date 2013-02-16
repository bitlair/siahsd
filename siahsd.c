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
#include "siahs.h"

#define MY_DEVICE "RCIPv2.4"


/* TODO:
 * - Move this interface file to pidl generated interface
 * - Add event connection to jsonbot
 * - Keep PROM state and monitor keepalives
 * - Make a load balancer that balances REGISTRATION REQUESTS to the proper port
 */


/*
 * send_reply sends a reply to a SIA-HS transmitter
 * It requires a memory context, the socket from which to reply, the socket address to reply to, the original packet
 * and a string with the reply message.
 * It returns nothing.
 */
static STATUS send_reply(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct siahs_packet *pkt, const char *string) {
	uint8_t *reply;
	int i;
	uint16_t sum = 0;
	uint32_t reply_len;

	reply_len = strlen(string) + 36;

 	reply = talloc_zero_array(mem_ctx, uint8_t, reply_len);
	NO_MEM_RETURN(reply);

	/* Store the length as network ordered uint32_t */
	*(uint32_t *)&reply[0] = htonl(reply_len - 4);

	/* No clue what these are */
	reply[4] = 0x01;
	reply[5] = 0x01;
	reply[6] = 0x80;
	reply[7] = 0x80;


	/* Add the device description */
	memcpy(&reply[8], MY_DEVICE, strlen(MY_DEVICE));

	/* Add the PROM code */
	*(uint16_t *)&reply[21] = htons(pkt->prom);

	/* No clue what these are */
	reply[24] = 0x1E;
	reply[25] = 0x03;
	reply[26] = 0x84; /* Maybe unencoded 0x01? */
	reply[27] = 0x03;

	/* Add the message */
	memcpy(&reply[34], string, strlen(string));

	/* Encode with XOR 0x85 and calculate checksum */
	for (i = 0; i < reply_len - 2; i++) {
		if (i >= 8)
			reply[i] ^= 0x85;

		sum += reply[i];
	}

	/* Store the checksum */
	*(uint16_t *)&reply[reply_len - 2] = htons(sum);


	DEBUG(4, "Sending %s sum %04x len %d\n", string, sum, reply_len - 4);

	sendto(sock, reply, reply_len, 0, (struct sockaddr *)&from, sizeof(from));

	/* Cleanup */
	talloc_free(reply);

	return ST_OK;
}


int main(int argc, char **argv) {
	int sock, n, i;
	socklen_t fromlen;
	struct sockaddr_in server;
	struct sockaddr_in from;
	TALLOC_CTX *mem_ctx;
	STATUS rv;
	FILE *pidfile;
	pid_t pid;
	const configuration *conf;

	set_process_name(argv[0]);

	/* Initialize a memory context */
	mem_ctx = talloc_init("siahsd");


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
	server.sin_port = htons(conf->siahs_port);
	server.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		DEBUG(0, "Could not bind to socket during startup (socket in use?)!");
		return ST_BIND_FAILURE;
	}


	DEBUG(0, "Started %s and waiting for SIA-HS packets on port %d", 
	         get_process_name(), conf->siahs_port);

	/*
	 * Wait for packets
	 */

	fromlen = sizeof(struct sockaddr_in);
	while (1) {
		uint16_t src_port;
		struct siahs_packet *pkt;
		uint8_t *decoded;
		uint8_t *buf = talloc_array(conf, uint8_t, 1024);
		char *reply_message;

		pkt = talloc_zero(mem_ctx, struct siahs_packet);

		NO_MEM_RETURN(pkt);

		n = recvfrom(sock, buf, 1024, 0, (struct sockaddr *) &from, &fromlen);
		if (n < 0) {
			DEBUG( 0, "Error when storing packet in buffer!");
			talloc_free(pkt);
			continue;
		} else if (n == 1024) {
			DEBUG(0, "Maximum packet size exceeded!");
			talloc_free(pkt);
			continue;
		}
		
		src_port = ntohs(from.sin_port);

		pkt->len = ntohl(*(uint32_t *)&buf[0]);

		if (pkt->len > n-4) {
			DEBUG(0, "Message length is longer than the packet (malformed packet!)");
			talloc_free(pkt);
			continue;
		}

		pkt->unknown1 = buf[4];
		pkt->unknown2 = buf[5];
		pkt->unknown3 = ntohs(*(uint16_t *)&buf[5]);

		decoded = talloc_memdup(pkt, &buf[8], pkt->len - 6);
		NO_MEM_RETURN(decoded);


		/* Decode with XOR 0xB6 */
		for (i = 0;i < pkt->len - 6; i++) {
			decoded[i] ^= 0xB6;
		}
		
		pkt->device = talloc_strndup(pkt, (char *)decoded, 12);
		NO_MEM_RETURN(pkt->device);

		pkt->prom = ntohs(*(uint16_t *)&decoded[13]);
		pkt->unknown4 = decoded[16];
		pkt->unknown5 = decoded[17];
		pkt->unknown6 = decoded[18];

		pkt->message = talloc_strndup(pkt, (char *) &decoded[26], pkt->len-32);
		NO_MEM_RETURN(pkt->message);

		DEBUG(3, "I have received device %s prom %x, message %s, from IP %s and port %u", 
		               pkt->device, pkt->prom, pkt->message, inet_ntoa(from.sin_addr), src_port);

		/* Handle registrations, reconnects and messages */
		if (strcmp(pkt->message, "REGISTRATION REQUEST") == 0) {

			/* XXX I'm sending this to this very same socket now. This should be used as a dispatcher */
			reply_message = talloc_asprintf(pkt, "REGISTRATION RENEWAL AT PORT %05d", conf->siahs_port);
			NO_MEM_RETURN(reply_message);

			send_reply(pkt, sock, from, pkt, reply_message);

		} else if (strcmp(pkt->message, "RECONNECT REQUEST") == 0) {

			/* This is the first message that arrives at the registration referred port  */
			reply_message = talloc_asprintf(pkt, "RECONNECTED AT PORT %05d", conf->siahs_port);
			NO_MEM_RETURN(reply_message);

			send_reply(pkt, sock, from, pkt, reply_message);
			

		} else if (strncmp(pkt->message, "MESSAGE ", strlen("MESSAGE ")) == 0) {
			char *pkt_prom;

			send_reply(pkt, sock, from, pkt, "ACKNOWLEDGE MESSAGE");
			pkt_prom = talloc_asprintf(pkt, "%04x", pkt->prom);
			parse_siahs_message(pkt, pkt_prom, pkt->message + strlen("MESSAGE "));

		} else {
			DEBUG(0, "Could not parse this message:\n"
			               "device: %s, prom: %x, msg: %s, from: %s:%u\n",
			               pkt->device, pkt->prom, pkt->message, 
			               inet_ntoa(from.sin_addr), src_port);
		}
	
		/* Clean up everything that's been attached to this packet */
		talloc_free(pkt);
	}
}

