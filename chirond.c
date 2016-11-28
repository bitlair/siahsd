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

// Function was licensed WTFPL, origin stack: overflow
// I am too lazy to write this myself, these days.
void hexdump (const char *desc, const void *addr, const int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        fprintf(stderr, "%s:\n", desc);

    if (len == 0) {
        fprintf(stderr, "  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        fprintf(stderr, "  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                fprintf(stderr, "  %s\n", buff);

            fprintf(stderr, "  %04x ", i);
        }

        fprintf(stderr, " %02x", pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        fprintf(stderr, "   ");
        i++;
    }

    fprintf(stderr, "  %s\n", buff);
}

struct chiron_context {
	int clientfd;
	struct sockaddr *clientaddr;
	char *account_code;
	char device_id[3];
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

struct ll_tlv {
	struct ll_tlv *next;
	enum chiron_msg_type type;
	uint8_t length;
	void *data_ptr;
};

STATUS tlv_to_linked_list(TALLOC_CTX *mem_ctx, DATA_BLOB data, struct ll_tlv **first_element) {
	uint8_t *tlvptr = data.data;
	struct ll_tlv *prev_elem = NULL;
	while (tlvptr + 2 < data.data + data.length) {
		struct ll_tlv *element = talloc_zero(mem_ctx, struct ll_tlv);
		if (prev_elem == NULL) {
			*first_element = element;
		} else {
			prev_elem->next = element;
		}

		element->type = *tlvptr++;

		element->length = *tlvptr++;
		if (tlvptr + element->length > data.data + data.length) {
			if (prev_elem != NULL) {
				prev_elem->next = NULL;
			}
			talloc_free(element);
			return ST_PARSE_ERROR;
		}
		element->data_ptr = tlvptr;


		tlvptr += element->length;
		prev_elem = element;
	}
	if (tlvptr < data.data + data.length) {
		DEBUG(1, "Error: Left over bytes in TLV");
		return ST_PARSE_ERROR;
	}
	return ST_OK;
}
STATUS handle_chiron_msg_ack(struct chiron_context *ctx, struct chiron_message *msg) {
	DEBUG(3, "Received ACK");
	return ST_OK;
}

STATUS send_chiron_msg_handshake(struct chiron_context *ctx, struct chiron_message *in) {
	struct chiron_message *out = talloc_zero(in, struct chiron_message);
	out->msg_type = CHIRON_HANDSHAKE;
	out->seq = in->seq;
	out->flags = 0xC0; /* FIXME: What does this do? */

	const uint8_t payload[] = { 0x27, 0, 0x32, 0, 0x18, 0, 0x2D, 0 };
	out->msg.handshake.data = talloc_memdup(out, payload, sizeof(payload));
	out->msg.handshake.length = sizeof(payload);

	struct arcfour_ctx rc4;
	arcfour_set_key(&rc4, MD5_HASH_LEN, ctx->rc4key);
	arcfour_crypt(&rc4, sizeof(payload), out->msg.handshake.data, payload);
	hexdump("Crypted outgoing payload", out->msg.handshake.data, sizeof(payload));

	DATA_BLOB raw_out;
	enum ndr_err_code ndr_err = ndr_push_struct_blob(&raw_out, out, out, (ndr_push_flags_fn_t)ndr_push_chiron_message);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Error writing NDR data blob.");
		return ST_WRITE_ERROR;
	}
	write(ctx->clientfd, raw_out.data, raw_out.length);
	talloc_free(out);
	return ST_OK;
}

STATUS handle_chiron_msg_response(struct chiron_context *ctx, struct chiron_message *msg) {
	DATA_BLOB crypted, decrypted;
	struct arcfour_ctx rc4;
	struct ll_tlv *element;

	if (memcmp(msg->msg.response.md5_check, ctx->md5_last_out, 0x10)) {
		DEBUG(0, "MD5 does not match!\n");
		return ST_PARSE_ERROR;
	}
	DEBUG(0, "Handling the response");

	/* Copy packet to crypted data blob */
	crypted.length = msg->msg.response.length - MD5_HASH_LEN;
	crypted.data = talloc_memdup(msg, msg->msg.response.payload, crypted.length);
	NO_MEM_RETURN(crypted.data);

	decrypted.data = talloc_array(msg, uint8_t, crypted.length);
	NO_MEM_RETURN(decrypted.data);
	decrypted.length = crypted.length;

	arcfour_set_key(&rc4, MD5_HASH_LEN, ctx->rc4key);
	arcfour_crypt(&rc4, crypted.length, decrypted.data, crypted.data);
	hexdump("Decrypted", decrypted.data, decrypted.length);

	/* The message starts with 3 bytes device_id, and then the TLV starts */
	memcpy(ctx->device_id, decrypted.data, 3);
	decrypted.data += 3;
	decrypted.length -= 3;

	tlv_to_linked_list(msg, decrypted, &element);
	while (element != NULL) {
		DEBUG(1, "Type: %x, Length: %d", element->type, element->length);
		hexdump("Data", element->data_ptr, element->length);
		element = element->next;
	}
	send_chiron_msg_handshake(ctx, msg);

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
#if 0
	out->msg.challenge.challenge[0] = 0xd0;
	out->msg.challenge.challenge[1] = 0x8b;
	out->msg.challenge.challenge[2] = 0x29;
	out->msg.challenge.challenge[3] = 0xd3;
	out->msg.challenge.challenge[4] = 0x7c;
	out->msg.challenge.challenge[5] = 0xfd;
	out->msg.challenge.challenge[6] = 0xb5;
	out->msg.challenge.challenge[7] = 0xc6;
	out->msg.challenge.challenge[8] = 0x1e;
#endif
//0x04, 0x0d, 0x49, 0xc1, 0x3d, 0xc8, 0x1f, 0x5f, 0x47
#if 0
	out->msg.challenge.challenge[0] = 0x04;
	out->msg.challenge.challenge[1] = 0x0d;
	out->msg.challenge.challenge[2] = 0x49;
	out->msg.challenge.challenge[3] = 0xc1;
	out->msg.challenge.challenge[4] = 0x3d;
	out->msg.challenge.challenge[5] = 0xc8;
	out->msg.challenge.challenge[6] = 0x1f;
	out->msg.challenge.challenge[7] = 0x5f;
	out->msg.challenge.challenge[8] = 0x47;
#endif
// 0x96, 0xf4, 0xc4, 0x86,
//        0xd9, 0x83, 0x4d, 0x87, 0x48
	out->msg.challenge.challenge[0] = 0x96;
	out->msg.challenge.challenge[1] = 0xf4;
	out->msg.challenge.challenge[2] = 0xc4;
	out->msg.challenge.challenge[3] = 0x86;
	out->msg.challenge.challenge[4] = 0xd9;
	out->msg.challenge.challenge[5] = 0x83;
	out->msg.challenge.challenge[6] = 0x4d;
	out->msg.challenge.challenge[7] = 0x87;
	out->msg.challenge.challenge[8] = 0x48;

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

STATUS handle_message(struct chiron_context *ctx, DATA_BLOB data) {
	struct chiron_message *msg;
	enum ndr_err_code ndr_err;
	STATUS status;
	msg = talloc(data.data, struct chiron_message);
	NO_MEM_RETURN(msg);

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
		case CHIRON_ACK:
			status = handle_chiron_msg_ack(ctx, msg);
			break;
		default:
			DEBUG(0, "Got unexpected message type: %s.",
				  ndr_print_chiron_msg_type_enum(msg, msg->msg_type));
			status = ST_NOT_IMPLEMENTED;
			break;
	}

	if (status != ST_OK) {
		return status;
	}

	talloc_free(msg);

	return ST_OK;
}

STATUS handle_connection(struct chiron_context *ctx) {
	int n;
	char buf[1024]; /* Purposefully static length */
	DATA_BLOB data;


	while ((n = read(ctx->clientfd, buf, sizeof(buf)))) {
		if (n < 0) {
			DEBUG( 0, "Error when storing packet in buffer!");
			return ST_PARSE_ERROR;
		} else if (n == sizeof(buf)) {
			DEBUG(0, "Maximum packet size exceeded!");
			return ST_PARSE_ERROR;
		}

		/* Copy packet to data blob */
		data.length = n;
		data.data = talloc_memdup(ctx, buf, n);
		NO_MEM_RETURN(data.data);

		talloc_free(data.data);
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
		if (pidfile == NULL)
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
		freeaddrinfo(first_server);
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
			if (client_ctx == NULL) {
				close(sock);
				close(clientfd);
				DEBUG(0, "Out of memory");
				return ST_OUT_OF_MEMORY;
			}
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
	struct chiron_context *client_ctx = talloc_zero(mem_ctx, struct chiron_context);
	NO_MEM_RETURN(client_ctx);
	client_ctx->clientfd = 1;
	client_ctx->clientaddr = (struct sockaddr *)talloc_zero(mem_ctx, struct sockaddr_storage);
#if 0
	// Account
	const uint8_t in_message1[] = { 0x41, 0x01, 0xa8, 0x04, 0x33, 0x35, 0x30, 0x30 };

	// Challenge
	const uint8_t out_message1[] = { 0x43, 0x01, 0xa8, 0x19, 0x28, 0xd5, 0xdc, 0x57,
	                          0x44, 0x77, 0x0d, 0xea, 0xc0, 0x03, 0x56, 0xca,
	                          0x42, 0x72, 0x18, 0x30, 0xd0, 0x8b, 0x29, 0xd3,
	                          0x7c, 0xfd, 0xb5, 0xc6, 0x1e };

	// Response
	const uint8_t in_message2[] = { 0x52, 0x01, 0xa8, 0x37, 0x62, 0x7f, 0xd0, 0xb8, 0xbc, 0x70, 0x6a, 0x44, 0x44, 0x21, 0x15, 0xb4, 0x94, 0x20, 0x62, 0x98, 0x7a, 0xe2, 0xde, 0xc2, 0xed, 0x76, 0x84, 0x5f, 0xe6, 0x16, 0x2b, 0x6b, 0xb9, 0x10, 0xa3, 0x6c, 0x14, 0x44, 0x56, 0xca, 0x45, 0xc6, 0xc2, 0xeb, 0xec, 0x1b, 0xd8, 0x7a, 0xa4, 0x4c, 0xc0, 0xb4, 0x88, 0x64, 0x6e, 0x2b, 0xee, 0x11, 0x54 };

	// Handshake
	const uint8_t out_message2[] = { 0x4b, 0x01, 0xc0, 0x08, 0x5d, 0x4f, 0x2b, 0xce, 0xf1, 0xde, 0x77, 0xa1 };

	// Ack
	const uint8_t in_message3[] = { 0x55, 0x01, 0xa8, 0x00 };
#endif
#if 0
	const uint8_t in_message1[] = { 0x41, 0x02, 0xa8, 0x04, 0x33, 0x35, 0x30, 0x30 };
	const uint8_t out_message1[] = { 0x43, 0x02, 0xa8, 0x19, 0x08, 0x71, 0x4f, 0xad, 0xed, 0xa3, 0xaf, 0x37, 0x88, 0xcc, 0x00, 0x51, 0xe4, 0xcb, 0xad, 0x7c, 0x04, 0x0d, 0x49, 0xc1, 0x3d, 0xc8, 0x1f, 0x5f, 0x47 };
	const uint8_t in_message2[] = { 0x52, 0x02, 0xa8, 0x46, 0xc8, 0xa8, 0xb6, 0x50, 0x34, 0xd5, 0x7a, 0x26, 0x90, 0x63, 0x92, 0x56, 0xe5, 0x4d, 0xde, 0xa0, 0x6a, 0x60, 0x19, 0xdc, 0x67, 0xbb, 0xe8, 0x9e, 0x8e, 0xfc, 0x79, 0x55, 0xed, 0x66, 0x26, 0x21, 0x1a, 0x6b, 0x4a, 0x9c, 0x7c, 0xe6, 0x1d, 0x01, 0xab, 0x57, 0xfb, 0xd9, 0x6d, 0x15, 0xbd, 0xe6, 0xe3, 0x94, 0xd6, 0xe7, 0xde, 0xc3, 0x89, 0x52, 0x65, 0x5f, 0x0c, 0x97, 0x4e, 0x4f, 0x6d, 0x9f, 0x5a, 0xb9, 0xc2, 0x12, 0xdd, 0x74 };

	const uint8_t out_message2[] = { 0x4b, 0x02, 0xc0, 0x00 };
#endif

	const uint8_t in_message1[] = {
		0x41, 0x03, 0x88, 0x04, 0x33, 0x35, 0x30, 0x30 };
	const uint8_t out_message1[] = {
		0x43, 0x03, 0x88, 0x19, 0xaa, 0xd9, 0xaa, 0x5f,
		0x30, 0x5d, 0x95, 0x0d, 0x96, 0x8d, 0x4e, 0x26,
		0x02, 0x1a, 0x1a, 0xd8, 0x96, 0xf4, 0xc4, 0x86,
		0xd9, 0x83, 0x4d, 0x87, 0x48 };
	const uint8_t in_message2[] = {
		0x52, 0x03, 0x88, 0x1f, 0xe5, 0x65, 0x48, 0x30,
		0x56, 0x8e, 0x3b, 0x42, 0x02, 0x6c, 0xcc, 0x9b,
		0xdc, 0x82, 0xb0, 0x17, 0xba, 0xef, 0x52, 0x61,
		0xe8, 0xce, 0x7b, 0xcb, 0x57, 0x85, 0x2b, 0x18,
		0xbf, 0xfa, 0xf1 };
	const uint8_t out_message2[] = {
		0x4b, 0x03, 0xc0, 0x00 };
	DATA_BLOB data;
	data.data = talloc_memdup(client_ctx, in_message1, sizeof(in_message1));
	data.length = sizeof(in_message1);
	handle_message(client_ctx, data);
	talloc_free(data.data);

	data.data = talloc_memdup(client_ctx, in_message2, sizeof(in_message2));
	data.length = sizeof(in_message2);
	handle_message(client_ctx, data);
	talloc_free(data.data);

	struct arcfour_ctx rc4;
	arcfour_set_key(&rc4, MD5_HASH_LEN, client_ctx->rc4key);
	uint8_t buf[sizeof(out_message2)] = {0};
	arcfour_crypt(&rc4, sizeof(out_message2) - 4, buf, out_message2 + 4);
	hexdump("Decrypted outgoing payload", buf, sizeof(out_message2) - 4);


	/*
	 * Open up a TCP socket the Chiron port
	 */
	//listen_server(mem_ctx, "::", CHIRON_PORT, "tcp", handle_connection);

	talloc_free(mem_ctx);
	return 0;
}
