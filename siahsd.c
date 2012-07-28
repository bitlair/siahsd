#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <talloc.h>
#include "siahs.h"
#include "sia.h"

#define MY_DEVICE "RCIPv2.4"


/* TODO:
 * - Make a load balancer that balances REGISTRATION REQUESTS to the proper port
 * - Actually do something with the messages: Add to database, keep state, etc
 */

void parse_message(TALLOC_CTX *mem_ctx, struct packet *pkt) {
	char *message = talloc_strdup(mem_ctx, pkt->message + strlen("MESSAGE "));
	char *ptr = message;
	char *prom = ptr;
	char *code;

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

	/* The remaining ptr contains the information string */

	
	/* Ignore alive! messages */
	if (strcmp(code, "alive!") == 0) {
		return;
	}

	printf("%s %s %s -- %s: %s\n", prom, code, ptr, sia_code_str(code), sia_code_desc(code));

	talloc_free(message);
}

void send_reply(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct packet *pkt, const char *string) {
	int n;
	uint8_t *reply;
	int i;
	uint16_t sum = 0;
	uint32_t reply_len;

	reply_len = strlen(string) + 36;

 	reply = talloc_zero_array(mem_ctx, uint8_t, reply_len);
	if (reply == NULL) return;

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


	printf("Sending %s sum %04x len %d\n", string, sum, reply_len - 4);

	n = sendto(sock, reply, reply_len, 0, (struct sockaddr *)&from, sizeof(from));

	/* Cleanup */
	talloc_free(reply);
}

int main(int argc, char **argv) {
	int sock, n, i;
	socklen_t fromlen;
	struct sockaddr_in server;
	struct sockaddr_in from;
	TALLOC_CTX *mem_ctx;

	/* Initialize a memory context */
	mem_ctx = talloc_init("siahsd");


	/*
	 * Open up a UDP socket on port 4000
	 */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) 
	 printf("Can not create socket in server\n");

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(4000);
	server.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		printf("Can not bind to socket!\n");
		exit(1);
	}


	/*
	 * Wait for packets
	 */
	fromlen = sizeof(struct sockaddr_in);
	while (1) {
		uint16_t src_port;
		struct packet *pkt;
		uint8_t *decoded;
		char buf[1024]; /* Purposefully static length */

		pkt = talloc_zero(mem_ctx, struct packet);

		n = recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &from, &fromlen);
		if (n < 0) {
			printf("Error when receiving in server!\n");
			talloc_free(pkt);
			continue;
		} else if (n == sizeof(buf)) {
			printf("Maximum packet size exceeded!\n");
			talloc_free(pkt);
			continue;
		}
		
		src_port = ntohs(from.sin_port);

		pkt->len = ntohl(*(uint32_t *)buf);

		if (pkt->len > n-4) {
			printf("Message length is longer than the packet (not possible!)\n");
			talloc_free(pkt);
			continue;
		}

		pkt->unknown1 = buf[4];
		pkt->unknown2 = buf[5];
		pkt->unknown3 = ntohs(*(uint16_t *)&buf[5]);

		decoded = talloc_memdup(pkt, &buf[8], pkt->len - 6);


		/* Decode with XOR 0xB6 */
		for (i = 0;i < pkt->len - 6; i++) {
			decoded[i] ^= 0xB6;
		}
		
		pkt->device = talloc_strndup(pkt, (char *)decoded, 12);

		pkt->prom = ntohs(*(uint16_t *)&decoded[13]);
		pkt->unknown4 = decoded[16];
		pkt->unknown5 = decoded[17];
		pkt->unknown6 = decoded[18];

		pkt->message = talloc_strndup(pkt, (char *) &decoded[26], pkt->len-32);

		printf("I have received device %s prom %x, message %s, from IP %s and port %u \n", pkt->device, pkt->prom, pkt->message, inet_ntoa(from.sin_addr), src_port);

		/* Handle registrations, reconnects and messages */
		if (strcmp(pkt->message, "REGISTRATION REQUEST") == 0) {

			send_reply(pkt, sock, from, pkt, "REGISTRATION RENEWAL AT PORT 04000");

		} else if (strcmp(pkt->message, "RECONNECT REQUEST") == 0) {

			send_reply(pkt, sock, from, pkt, "RECONNECTED AT PORT 04000");

		} else if (strncmp(pkt->message, "MESSAGE ", strlen("MESSAGE ")) == 0) {

			send_reply(pkt, sock, from, pkt, "ACKNOWLEDGE MESSAGE");
			parse_message(pkt, pkt);

		} else {
			printf("==============================================\n"
			       "ERROR: Could not parse this message\n"
			       "==============================================\n");
		}
	
		/* Clean up everything that's been attached to this packet */
		talloc_free(pkt);
	}
}

