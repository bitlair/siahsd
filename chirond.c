/*
   Chiron IP Alarm Monitoring Service
   Copyright (C) Wilco Baan Hofman <wilco@baanhofman.nl> 2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 4 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "includes.h"
#include "build/ndr_chiron.h"
#include "build/chiron.h"
#include <nettle/md5.h>
#include <nettle/arcfour.h>

#define CHIRON_PORT "53165"

struct chiron_context {
	int clientfd;
	struct sockaddr *clientaddr;
	char *account_code;
	char *device_id;
	uint8_t md5_last_out[0x10];
	uint8_t rc4key[0x10];
};

/* FIXME This function is a nasty little hack. */
char *ndr_print_chiron_msg_type_enum(TALLOC_CTX *mem_ctx, enum chiron_msg_type msg_type) {
	char *ret;
	struct ndr_print *ndr_print = talloc_zero(mem_ctx, struct ndr_print);
	ndr_print->print = ndr_print_string_helper;
	ndr_print->depth = 0;
	ndr_print_chiron_msg_type(ndr_print, "", msg_type);
	ret = talloc_steal(mem_ctx, ndr_print->private_data);
	talloc_free(ndr_print);
	return ret;
}

STATUS handle_chiron_msg_response(struct chiron_context *ctx, struct chiron_message *msg) {
#if 0 // TLV, move to ASN.1 parsing
	DATA_BLOB crypted, decrypted;
	enum ndr_err_code ndr_err;
	struct chiron_msg_inner_response *inner_response;
	struct arcfour_ctx rc4;
	char *deviceid_string;

	if (memcmp(msg->msg.response.md5_check, ctx->md5_last_out, 0x10)) {
		DEBUG(0, "MD5 does not match!\n");
		return ST_PARSE_ERROR;
	}
	DEBUG(0, "Handling the response");
	inner_response = talloc(msg, struct chiron_msg_inner_response);
	NO_MEM_RETURN(inner_response);

	/* Copy packet to crypted data blob */
	crypted.length = msg->msg.response.length - MD5_HASH_LEN;
	crypted.data = talloc_memdup(msg, msg->msg.response.payload, crypted.length);
	NO_MEM_RETURN(crypted.data);

	decrypted.data = talloc_array(msg, uint8_t, crypted.length);
	NO_MEM_RETURN(decrypted.data);
	decrypted.length = crypted.length;
 
	arcfour_set_key(&rc4, MD5_HASH_LEN, ctx->rc4key);
	arcfour_crypt(&rc4, crypted.length, decrypted.data, crypted.data);

	/* Parse the packet */
	ndr_err = ndr_pull_struct_blob_all(&decrypted, inner_response, inner_response, (ndr_pull_flags_fn_t)ndr_pull_chiron_msg_inner_response);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Could not parse the inner response");
		return ST_PARSE_ERROR;
	}
	DEBUG(0, "%s", ndr_print_struct_string(msg,(ndr_print_fn_t)ndr_print_chiron_msg_inner_response, "chiron payload", inner_response));
	
	deviceid_string = talloc_zero_array(msg, char, inner_response->dev_len + 1);
	memcpy(deviceid_string, inner_response->deviceid, inner_response->dev_len);

	DEBUG(0, "Remote device: %s", deviceid_string);
#endif
	//send_chiron_msg_key
	return ST_OK;
}


STATUS send_chiron_msg_challenge(struct chiron_context *ctx, struct chiron_message *in) {
	struct chiron_message *out = talloc_zero(in, struct chiron_message);
	struct md5_ctx md5;
	uint8_t *md5input;
	enum ndr_err_code ndr_err;
	DATA_BLOB raw_out;

	NO_MEM_RETURN(out);
	DEBUG(0, "Sending out a challenge");

	out->msg_type = CHIRON_CHALLENGE;
	out->seq = in->seq;
	out->flags = in->flags;

	/* Make an md5 hash of the account code with the seq byte appended. */
	md5input = talloc_array(in, uint8_t, in->msg.account.length + 1);
	NO_MEM_RETURN(md5input);
	
	memcpy(md5input, in->msg.account.account_code, in->msg.account.length);
	md5input[in->msg.account.length] = in->seq;
	
	out->msg.challenge.md5_check = talloc_array(out, uint8_t, MD5_HASH_LEN);
	NO_MEM_RETURN(out->msg.challenge.md5_check);

	md5_init(&md5);
	md5_update(&md5, in->msg.account.length + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, out->msg.challenge.md5_check);
	talloc_free(md5input);

	/* FIXME This should be random, but that is annoying for testing purposes */
	out->msg.challenge.length = MD5_HASH_LEN + CHALLENGE_LEN;
	out->msg.challenge.challenge = talloc_zero_array(out, uint8_t, CHALLENGE_LEN);
	NO_MEM_RETURN(out->msg.challenge.challenge);
	out->msg.challenge.challenge[0] = 0xd0;
	out->msg.challenge.challenge[1] = 0x8b;
	out->msg.challenge.challenge[2] = 0x29;
	out->msg.challenge.challenge[3] = 0xd3;
	out->msg.challenge.challenge[4] = 0x7c;
	out->msg.challenge.challenge[5] = 0xfd;
	out->msg.challenge.challenge[6] = 0xb5;
	out->msg.challenge.challenge[7] = 0xc6;
	out->msg.challenge.challenge[8] = 0x1e;

	ndr_err = ndr_push_struct_blob(&raw_out, out, out, (ndr_push_flags_fn_t)ndr_push_chiron_message);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Error writing NDR data blob.");
		return ST_WRITE_ERROR;
	}

	/* Update the md5 check for the next message (last 9 bytes with the seq byte appended). */
	md5input = talloc_array(in, uint8_t, CHALLENGE_LEN + 1);
	NO_MEM_RETURN(md5input);

	memcpy(md5input, &raw_out.data[MSG_HDR_LEN + MD5_HASH_LEN], CHALLENGE_LEN);
	md5input[CHALLENGE_LEN] = in->seq;

	md5_init(&md5);
	md5_update(&md5, CHALLENGE_LEN + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, ctx->md5_last_out);

	/* Update the rc4 crypto key, which is seq+challenge */
	md5input[0] = in->seq;
	memcpy(&md5input[1], &raw_out.data[MSG_HDR_LEN + MD5_HASH_LEN], CHALLENGE_LEN);

	md5_init(&md5);
	md5_update(&md5, CHALLENGE_LEN + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, ctx->rc4key);

	DEBUG(0, "The expected md5sum for the next entry is %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
	      ctx->md5_last_out[0], ctx->md5_last_out[1], ctx->md5_last_out[2], ctx->md5_last_out[3],
	      ctx->md5_last_out[4], ctx->md5_last_out[5], ctx->md5_last_out[6], ctx->md5_last_out[9],
	      ctx->md5_last_out[8], ctx->md5_last_out[9], ctx->md5_last_out[10], ctx->md5_last_out[11],
	      ctx->md5_last_out[12], ctx->md5_last_out[13], ctx->md5_last_out[14], ctx->md5_last_out[15]);

	write(ctx->clientfd, raw_out.data, raw_out.length);
	talloc_free(out);
	return ST_OK;
}

STATUS handle_chiron_msg_account(struct chiron_context *ctx, struct chiron_message *msg) {

	ctx->account_code = talloc_memdup(msg, msg->msg.account.account_code, msg->msg.account.length);
	NO_MEM_RETURN(ctx->account_code);
	
	send_chiron_msg_challenge(ctx, msg);
	return ST_OK;	
}

STATUS handle_connection(struct chiron_context *ctx) {
	int n;
	struct chiron_message *msg;
	enum ndr_err_code ndr_err;
	char buf[1024]; /* Purposefully static length */
	DATA_BLOB data;
	STATUS status;


	while ((n = read(ctx->clientfd, buf, sizeof(buf)))) {
		if (n < 0) {
			DEBUG( 0, "Error when storing packet in buffer!");
			return ST_PARSE_ERROR;
		} else if (n == sizeof(buf)) {
			DEBUG(0, "Maximum packet size exceeded!");
			return ST_PARSE_ERROR;
		}

		msg = talloc(ctx, struct chiron_message);
		NO_MEM_RETURN(msg);

		/* Copy packet to data blob */
		data.length = n;
		data.data = talloc_memdup(msg, buf, n);
		NO_MEM_RETURN(data.data);
		
		/* Parse the packet */
		ndr_err = ndr_pull_struct_blob_all(&data, msg, msg, (ndr_pull_flags_fn_t)ndr_pull_chiron_message);

		if (ndr_err != NDR_ERR_SUCCESS) {
			DEBUG(0, "Could not parse this message");
			return ST_PARSE_ERROR;
		}
		DEBUG(0, "%s", ndr_print_struct_string(msg,(ndr_print_fn_t)ndr_print_chiron_message, "chiron message", msg));

		switch (msg->msg_type) {
			case CHIRON_ACCOUNT:
				status = handle_chiron_msg_account(ctx, msg);
				break;
			case CHIRON_RESPONSE:
				status = handle_chiron_msg_response(ctx, msg);
				break;
			default:
				DEBUG(0, "Got unexpected message type: %s.", 
				      ndr_print_chiron_msg_type_enum(msg, msg->msg_type));
				break;
		}

		if (status != ST_OK) {
			return status;
		}

		talloc_free(msg);
	}
	return ST_OK;
}

static STATUS daemonize(char *pid_file) {
	FILE *pidfile;
	pid_t pid;

	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	if ((pid = fork())) {
		/* Write PID file */
		pidfile = fopen(pid_file, "w");
		if (pidfile < 0)
			exit(1);

		fprintf(pidfile, "%d\n", pid);
		fclose(pidfile);
		exit(0);
	}
	return ST_OK;
}

static STATUS listen_server(TALLOC_CTX *mem_ctx, const char *bindaddr, const char *bindport, const char *protocol, STATUS (*dispatcher)(struct chiron_context *)) {
	int sock;
	socklen_t clientlen;
	struct addrinfo hints, *server, *first_server;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags    = AI_PASSIVE;

	getaddrinfo(bindaddr, bindport, &hints, &server);

	first_server = server;
	while (server) {
		sock = socket(server->ai_family, SOCK_STREAM, 0);
		if (sock >= 0) {
			int optval = 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
			if (bind(sock, server->ai_addr, server->ai_addrlen) < 0) {
				close(sock);
				sock = -1;
			} else {
				break;
			}
		}
		server = server->ai_next;
	}

	if (sock < 0) {
		DEBUG(0, "Could not create socket in server");
		return ST_SOCKET_FAILURE;
	}
	listen(sock, 128);
	freeaddrinfo(first_server);

	DEBUG(0, "Started %s and waiting for Chiron messages on port %s", 
	         get_process_name(), CHIRON_PORT);

	/*
	 * Wait for connections
	 */

	clientlen = sizeof(struct addrinfo);
	while (1) {
		int clientfd;
		struct sockaddr_storage clientaddr;
		char clienthost[NI_MAXHOST];
		char clientservice[NI_MAXSERV];

		clientfd = accept(sock, (struct sockaddr *)&clientaddr, &clientlen);
		getnameinfo((struct sockaddr *)&clientaddr, clientlen,
			    clienthost, sizeof(clienthost),
			    clientservice, sizeof(clientservice),
			    NI_NUMERICHOST | NI_NUMERICSERV);
		DEBUG(3, "Received connection from %s:%s", clienthost, clientservice);

		//if (fork()) {
		//	continue;
		//} else {
		{
			struct chiron_context *client_ctx = talloc_zero(mem_ctx, struct chiron_context);
			NO_MEM_RETURN(client_ctx);
			client_ctx->clientaddr = (struct sockaddr *)&clientaddr;
			client_ctx->clientfd = clientfd;

			dispatcher(client_ctx);

			shutdown(client_ctx->clientfd, SHUT_RDWR);
			close(client_ctx->clientfd);

			talloc_free(client_ctx);
			exit(0);
		}

	}
	shutdown(sock, SHUT_RDWR);
	close(sock);
}

int main (int argc, char **argv) {
	TALLOC_CTX *mem_ctx;
	STATUS rv;
	const configuration *conf;

	set_process_name(argv[0]);

	/* Initialize a memory context */
	mem_ctx = talloc_init("chirond");

	/* Read the configuration file */
	rv = read_configuration_file(mem_ctx);
	if (rv != ST_OK)
		return rv;

	conf = get_conf();

	/* Daemonize if we're not supposed to run in foreground mode */
	if (!conf->foreground) {
		daemonize(conf->pid_file);
	}

	/*
	 * Open up a TCP socket the Chiron port
	 */
	listen_server(mem_ctx, "::", CHIRON_PORT, "tcp", handle_connection);

	return 0;
}
