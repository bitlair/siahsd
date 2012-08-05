/*
	JSONBot event generator
	Alarm Monitoring Service
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
#include <nettle/aes.h>


STATUS jsonbot_notify(TALLOC_CTX *mem_ctx, dbi_conn conn, const char *prom, const char *code, const char *description)
{
	int sockfd;
	struct sockaddr_in servaddr;
	const configuration *conf;
	char *outtext;
	struct aes_ctx aes;
	uint8_t *msgbuf, *msgbuf_crypted;
	uint16_t msglen;

	conf = get_conf();


	aes_set_encrypt_key(&aes, strlen(conf->jsonbot_aeskey), (uint8_t *) conf->jsonbot_aeskey);

	outtext = talloc_asprintf(mem_ctx, "%s %s Event at prom %s: %s: %s: %s -- %s\n",
			conf->jsonbot_password, conf->jsonbot_privmsg_to, prom, description, code,
			sia_code_str(code), sia_code_desc(code));


	msglen = (strlen(outtext) + 1) + (16 - ((strlen(outtext) + 1) % 16));

	msgbuf = talloc_zero_array(mem_ctx, uint8_t, msglen + 1);
	msgbuf_crypted = talloc_array(mem_ctx, uint8_t, msglen + 1);

	memcpy(msgbuf, outtext, strlen(outtext));

	aes_encrypt(&aes, msglen, msgbuf_crypted, msgbuf);

	/*
	 * Set up the outgoing UDP socket
	 */
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		DEBUG(0, "Failed to set up UDP socket for jsonbot");
		return ST_GENERAL_FAILURE;
	}
	
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(conf->jsonbot_port);
	servaddr.sin_addr.s_addr = inet_addr(conf->jsonbot_address);

	if (sendto(sockfd, msgbuf_crypted, msglen, 0,
	       (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		DEBUG(0, "Failed to send UDP packet to %s:%d", conf->jsonbot_address, conf->jsonbot_port);
		return ST_GENERAL_FAILURE;
	}

	return ST_OK;
}
