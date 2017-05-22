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
	uint8_t md5_last_out[MD5_HASH_LEN];
	uint8_t rc4key[MD5_HASH_LEN];
	bool alt_format;
	uint8_t seq;
	uint8_t flags;
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
STATUS handle_chiron_msg_ack(struct chiron_context *ctx, struct chiron_msg_ack *ack) {
	DEBUG(3, "Received ACK");
	return ST_OK;
}

STATUS send_chiron_msg_handshake1(struct chiron_context *ctx, struct chiron_msg_response *response) {
	struct chiron_message *out = talloc_zero(response, struct chiron_message);
	out->msg_type = CHIRON_HANDSHAKE1;
	out->seq = ctx->seq;
	out->flags = 0xC0; /* FIXME: What does this do? */

	const uint8_t payload[] = { 0x27, 0, 0x32, 0, 0x18, 0, 0x2D, 0 };
	out->msg.handshake1.data = talloc_memdup(out, payload, sizeof(payload));
	out->msg.handshake1.length = sizeof(payload);

	struct arcfour_ctx rc4;
	arcfour_set_key(&rc4, MD5_HASH_LEN, ctx->rc4key);
	arcfour_crypt(&rc4, sizeof(payload), out->msg.handshake1.data, payload);
	hexdump("Crypted outgoing payload", out->msg.handshake1.data, sizeof(payload));

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
STATUS send_chiron_altmsg_handshake2(struct chiron_context *ctx, struct chiron_msg_response *response) {
	struct chiron_alt_message *alt = talloc_zero(response, struct chiron_alt_message);

	DEBUG(0, "Sending out an alt handshake2");
	alt = talloc_zero(response, struct chiron_alt_message);
	NO_MEM_RETURN(alt);
	alt->msg_type = CHIRON_HANDSHAKE2;
	alt->seq = ctx->seq;
	alt->something01 = 0x01;
	alt->otherthing01 = 0x01;
	alt->someflag = ctx->flags;
	alt->something00 = 0x00;
	alt->length = 0x0B;

	struct chiron_msg_handshake2 *handshake2 = &alt->msg.handshake2;
	//int hdrlen = ALTMSG_HDR_LEN;

	handshake2->length = CHALLENGE_LEN;
	handshake2->challenge = talloc_zero_array(alt, uint8_t, CHALLENGE_LEN);
	NO_MEM_RETURN(handshake2->challenge);
	handshake2->challenge[0] = 0x07;
	handshake2->challenge[1] = 0x2f;
	handshake2->challenge[2] = 0xb9;
	handshake2->challenge[3] = 0x81;
	handshake2->challenge[4] = 0x3d;
	handshake2->challenge[5] = 0x0f;
	handshake2->challenge[6] = 0x14;
	handshake2->challenge[7] = 0xac;
	handshake2->challenge[8] = 0x59;

	DATA_BLOB raw_out;
	enum ndr_err_code ndr_err = ndr_push_struct_blob(&raw_out, alt, alt, (ndr_push_flags_fn_t)ndr_push_chiron_alt_message);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Error writing NDR data blob.");
		return ST_WRITE_ERROR;
	}

	/* Update the rc4 crypto key, which is seq+challenge */
	uint8_t *md5input = talloc_array(response, uint8_t, CHALLENGE_LEN + 1);
	NO_MEM_RETURN(md5input);

	int count = write(ctx->clientfd, raw_out.data, raw_out.length);
	if (count < 0) {
		DEBUG(0, "Error during write of %d bytes to fd %d: %s", raw_out.length, ctx->clientfd, strerror(errno));
	} else if ((unsigned)count < raw_out.length) {
		DEBUG(0, "Short write during writing out the raw_data with length %d", raw_out.length);
	}

	talloc_free(alt);
	return ST_OK;
}

STATUS handle_chiron_msg_response(struct chiron_context *ctx, struct chiron_msg_response *response) {
	DATA_BLOB crypted, decrypted;
	struct arcfour_ctx rc4;
	struct ll_tlv *element;

	if (memcmp(response->md5_check, ctx->md5_last_out, 0x10)) {
		DEBUG(0, "MD5 does not match!\n");
		return ST_PARSE_ERROR;
	}
	DEBUG(0, "Handling the response");

	/* Copy packet to crypted data blob */
	crypted.length = response->length - MD5_HASH_LEN;
	if (crypted.length > 0) {
		crypted.data = talloc_memdup(response, response->payload, crypted.length);
		NO_MEM_RETURN(crypted.data);

		decrypted.data = talloc_array(response, uint8_t, crypted.length);
		NO_MEM_RETURN(decrypted.data);
		decrypted.length = crypted.length;

		arcfour_set_key(&rc4, MD5_HASH_LEN, ctx->rc4key);
		arcfour_crypt(&rc4, crypted.length, decrypted.data, crypted.data);
		hexdump("Decrypted", decrypted.data, decrypted.length);

		/* The message starts with 3 bytes device_id, and then the TLV starts */
		memcpy(ctx->device_id, decrypted.data, 3);
		decrypted.data += 3;
		decrypted.length -= 3;

		tlv_to_linked_list(response, decrypted, &element);
		while (element != NULL) {
			DEBUG(1, "Type: %x, Length: %d", element->type, element->length);
			hexdump("Data", element->data_ptr, element->length);
			element = element->next;
		}
		send_chiron_msg_handshake1(ctx, response);
	} else {
		send_chiron_altmsg_handshake2(ctx, response);
	}
	return ST_OK;
}
STATUS send_chiron_altmsg_challenge(struct chiron_context *ctx, struct chiron_msg_account *account) {
	struct chiron_alt_message *alt;
	struct md5_ctx md5;
	uint8_t *md5input;
	enum ndr_err_code ndr_err;
	DATA_BLOB raw_out;
	struct chiron_altmsg_challenge *challenge;
	int hdrlen;

	DEBUG(0, "Sending out an alt challenge");
	alt = talloc_zero(account, struct chiron_alt_message);
	NO_MEM_RETURN(alt);
	alt->msg_type = CHIRON_CHALLENGE;
	alt->seq = ctx->seq;
	alt->something01 = 0x01;
	alt->otherthing01 = 0x01;
	alt->someflag = ctx->flags;
	alt->something00 = 0x00;
	alt->length = 0x0B;

	challenge = &alt->msg.challenge;
	hdrlen = ALTMSG_HDR_LEN;

	/* FIXME This should be random, but that is annoying for testing purposes */
	challenge->length = CHALLENGE_LEN;
	challenge->challenge = talloc_zero_array(alt, uint8_t, CHALLENGE_LEN);
	NO_MEM_RETURN(challenge->challenge);
	challenge->challenge[0] = 0x60;
	challenge->challenge[1] = 0x19;
	challenge->challenge[2] = 0x12;
	challenge->challenge[3] = 0xa8;
	challenge->challenge[4] = 0x91;
	challenge->challenge[5] = 0x45;
	challenge->challenge[6] = 0x89;
	challenge->challenge[7] = 0x8f;
	challenge->challenge[8] = 0x37;

	ndr_err = ndr_push_struct_blob(&raw_out, alt, alt, (ndr_push_flags_fn_t)ndr_push_chiron_alt_message);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Error writing NDR data blob.");
		return ST_WRITE_ERROR;
	}

	/* Update the rc4 crypto key, which is seq+challenge */
	md5input = talloc_array(account, uint8_t, CHALLENGE_LEN + 1);
	NO_MEM_RETURN(md5input);
	md5input[0] = ctx->seq;
	memcpy(&md5input[1], &raw_out.data[hdrlen], CHALLENGE_LEN);

	md5_init(&md5);
	md5_update(&md5, CHALLENGE_LEN + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, ctx->rc4key);


	/* Update the md5 check for the next message (last 9 bytes with the seq byte appended). */
	memcpy(md5input, &raw_out.data[hdrlen], CHALLENGE_LEN);
	md5input[CHALLENGE_LEN] = ctx->seq;

	md5_init(&md5);
	md5_update(&md5, CHALLENGE_LEN + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, ctx->md5_last_out);



	int count = write(ctx->clientfd, raw_out.data, raw_out.length);
	if (count < 0) {
		DEBUG(0, "Error during write of %d bytes to fd %d: %s", raw_out.length, ctx->clientfd, strerror(errno));
	} else if ((unsigned)count < raw_out.length) {
		DEBUG(0, "Short write during writing out the raw_data with length %d", raw_out.length);
	}
	/* Update the md5 check for the next message (last 9 bytes with the seq byte appended). */

	talloc_free(alt);
	return ST_OK;
}

STATUS send_chiron_msg_challenge(struct chiron_context *ctx, struct chiron_msg_account *account) {
	struct chiron_message *out;
	struct md5_ctx md5;
	uint8_t *md5input;
	enum ndr_err_code ndr_err;
	DATA_BLOB raw_out;
	struct chiron_msg_challenge *challenge;
	int hdrlen;

	DEBUG(0, "Sending out a challenge");
	out = talloc_zero(account, struct chiron_message);
	NO_MEM_RETURN(out);
	out->msg_type = CHIRON_CHALLENGE;
	out->seq = ctx->seq;
	out->flags = ctx->flags;

	challenge = &out->msg.challenge;
	hdrlen = MSG_HDR_LEN;

	/* Make an md5 hash of the account code with the seq byte appended. */
	md5input = talloc_array(account, uint8_t, account->length + 1);
	NO_MEM_RETURN(md5input);

	memcpy(md5input, account->account_code, account->length);
	md5input[account->length] = ctx->seq;

	challenge->md5_check = talloc_array(account, uint8_t, MD5_HASH_LEN);
	NO_MEM_RETURN(challenge->md5_check);

	md5_init(&md5);
	md5_update(&md5, account->length + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, challenge->md5_check);
	talloc_free(md5input);


	/* FIXME This should be random, but that is annoying for testing purposes */
	challenge->length = MD5_HASH_LEN + CHALLENGE_LEN;
	challenge->challenge = talloc_zero_array(account, uint8_t, CHALLENGE_LEN);
	NO_MEM_RETURN(challenge->challenge);
	challenge->challenge[0] = 0xd0;
	challenge->challenge[1] = 0x8b;
	challenge->challenge[2] = 0x29;
	challenge->challenge[3] = 0xd3;
	challenge->challenge[4] = 0x7c;
	challenge->challenge[5] = 0xfd;
	challenge->challenge[6] = 0xb5;
	challenge->challenge[7] = 0xc6;
	challenge->challenge[8] = 0x1e;

	ndr_err = ndr_push_struct_blob(&raw_out, out, out, (ndr_push_flags_fn_t)ndr_push_chiron_message);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Error writing NDR data blob.");
		return ST_WRITE_ERROR;
	}

	/* Update the md5 check for the next message (last 9 bytes with the seq byte appended). */
	md5input = talloc_array(account, uint8_t, CHALLENGE_LEN + 1);
	NO_MEM_RETURN(md5input);

	memcpy(md5input, &raw_out.data[hdrlen + MD5_HASH_LEN], CHALLENGE_LEN);
	md5input[CHALLENGE_LEN] = ctx->seq;


	md5_init(&md5);
	md5_update(&md5, CHALLENGE_LEN + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, ctx->md5_last_out);

	/* Update the rc4 crypto key, which is seq+challenge */
	md5input[0] = ctx->seq;
	memcpy(&md5input[1], &raw_out.data[hdrlen + MD5_HASH_LEN], CHALLENGE_LEN);

	md5_init(&md5);
	md5_update(&md5, CHALLENGE_LEN + 1, md5input);
	md5_digest(&md5, MD5_HASH_LEN, ctx->rc4key);

	DEBUG(0, "The expected md5sum for the next entry is %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		  ctx->md5_last_out[0], ctx->md5_last_out[1], ctx->md5_last_out[2], ctx->md5_last_out[3],
		  ctx->md5_last_out[4], ctx->md5_last_out[5], ctx->md5_last_out[6], ctx->md5_last_out[9],
		  ctx->md5_last_out[8], ctx->md5_last_out[9], ctx->md5_last_out[10], ctx->md5_last_out[11],
		  ctx->md5_last_out[12], ctx->md5_last_out[13], ctx->md5_last_out[14], ctx->md5_last_out[15]);

	int count = write(ctx->clientfd, raw_out.data, raw_out.length);
	if (count < 0) {
		DEBUG(0, "Error during write of %d bytes to fd %d: %s", raw_out.length, ctx->clientfd, strerror(errno));
	} else if ((unsigned)count < raw_out.length) {
		DEBUG(0, "Short write during writing out the raw_data with length %d", raw_out.length);
	}
	talloc_free(out);
	return ST_OK;
}

STATUS handle_chiron_msg_account(struct chiron_context *ctx, struct chiron_msg_account *account) {

	ctx->account_code = talloc_memdup(account, account->account_code, account->length);
	NO_MEM_RETURN(ctx->account_code);

	if (!ctx->alt_format) {
		return send_chiron_msg_challenge(ctx, account);
	} else {
		return send_chiron_altmsg_challenge(ctx, account);
	}
}

STATUS send_chiron_altmsg_ack(struct chiron_context *ctx, struct chiron_msg_signal *signal) {
	struct chiron_alt_message *alt;
	enum ndr_err_code ndr_err;
	DATA_BLOB raw_out;

	DEBUG(0, "Sending out an alt ack");
	alt = talloc_zero(signal, struct chiron_alt_message);
	NO_MEM_RETURN(alt);
	alt->msg_type = CHIRON_ACCOUNT;
	alt->seq = ctx->seq;
	alt->something01 = 0x01;
	alt->otherthing01 = 0x01;
	alt->someflag = ctx->flags;
	alt->something00 = 0x00;
	alt->length = 0x02;
	alt->msg.account.length = 0;

	ndr_err = ndr_push_struct_blob(&raw_out, alt, alt, (ndr_push_flags_fn_t)ndr_push_chiron_alt_message);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Error writing NDR data blob.");
		return ST_WRITE_ERROR;
	}
	int count = write(ctx->clientfd, raw_out.data, raw_out.length);
	if (count < 0) {
		DEBUG(0, "Error during write of %d bytes to fd %d: %s", raw_out.length, ctx->clientfd, strerror(errno));
	} else if ((unsigned)count < raw_out.length) {
		DEBUG(0, "Short write during writing out the raw_data with length %d", raw_out.length);
	}
	talloc_free(alt);
	return ST_OK;
}
STATUS handle_chiron_msg_signal(struct chiron_context *ctx, struct chiron_msg_signal *signal) {
	DATA_BLOB crypted, decrypted;
	struct arcfour_ctx rc4;

	/* Copy packet to crypted data blob */
	crypted.length = signal->length+6;
	crypted.data = talloc_memdup(signal, signal->data, crypted.length);
	NO_MEM_RETURN(crypted.data);
	decrypted.data = talloc_array(signal, uint8_t, crypted.length);
	NO_MEM_RETURN(decrypted.data);
	decrypted.length = crypted.length;

	arcfour_set_key(&rc4, MD5_HASH_LEN, ctx->rc4key);
	arcfour_crypt(&rc4, crypted.length, decrypted.data, crypted.data);
	hexdump("Decrypted", decrypted.data, decrypted.length);

	return send_chiron_altmsg_ack(ctx, signal);
}

STATUS handle_message(struct chiron_context *ctx, DATA_BLOB data) {

	struct chiron_message *msg = talloc(data.data, struct chiron_message);
	NO_MEM_RETURN(msg);
	struct chiron_alt_message *alt_msg = talloc(data.data, struct chiron_alt_message);
	NO_MEM_RETURN(msg);

	/* Parse the packet */
	enum ndr_err_code ndr_err;
	if (data.length > 0 && data.data[0] != 1) {
		ctx->alt_format = 0;
		ndr_err = ndr_pull_struct_blob_all(&data, msg, msg, (ndr_pull_flags_fn_t)ndr_pull_chiron_message);
	} else {
		ctx->alt_format = 1;
		ndr_err = ndr_pull_struct_blob_all(&data, alt_msg, alt_msg, (ndr_pull_flags_fn_t)ndr_pull_chiron_alt_message);
	}

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Could not parse this message");
		hexdump("Message bytes", data.data, data.length);
		return ST_PARSE_ERROR;
	}
	enum chiron_msg_type msg_type;
	if (ctx->alt_format) {
		ctx->seq = alt_msg->seq;
		ctx->flags = 0;
		msg_type = alt_msg->msg_type;
		DEBUG(0, "%s", ndr_print_struct_string(msg,(ndr_print_fn_t)ndr_print_chiron_alt_message, "chiron alt message", alt_msg));
	} else {
		ctx->seq = msg->seq;
		ctx->flags = msg->flags;
		msg_type = msg->msg_type;
		DEBUG(0, "%s", ndr_print_struct_string(msg,(ndr_print_fn_t)ndr_print_chiron_message, "chiron message", msg));
	}
	STATUS status;
	switch (msg_type) {
		case CHIRON_ACCOUNT: {
			struct chiron_msg_account *account;
			if (ctx->alt_format) {
				account = talloc_memdup(alt_msg, &alt_msg->msg.account, sizeof(struct chiron_msg_account));
			} else {
				account = talloc_memdup(msg, &msg->msg.account, sizeof(struct chiron_msg_account));
			}
			DEBUG(0, "Got chiron_msg_account");
			status = handle_chiron_msg_account(ctx, account);
			break;
		}
		case CHIRON_RESPONSE: {
			struct chiron_msg_response *response;
			if (ctx->alt_format) {
				response = talloc_memdup(alt_msg, &alt_msg->msg.response.response, sizeof(struct chiron_msg_response));
			} else {
				response = talloc_memdup(msg, &msg->msg.response, sizeof(struct chiron_msg_response));
			}
			DEBUG(0, "Got chiron_msg_response");
			status = handle_chiron_msg_response(ctx, response);
			break;
		}
		case CHIRON_ACK: {
			struct chiron_msg_ack *ack;
			if (ctx->alt_format) {
				ack = talloc_memdup(alt_msg, &alt_msg->msg.ack, sizeof(struct chiron_msg_ack));
			} else {
				ack = talloc_memdup(msg, &msg->msg.ack, sizeof(struct chiron_msg_ack));
			}
			DEBUG(0, "Got chiron_msg_ack");
			status = handle_chiron_msg_ack(ctx, ack);
			break;
		}
		case CHIRON_SIGNAL: {
			struct chiron_msg_signal *signal;
			if (ctx->alt_format) {
				signal = talloc_memdup(alt_msg, &alt_msg->msg.signal, sizeof(struct chiron_msg_signal));
			} else {
				signal = talloc_memdup(msg, &msg->msg.signal, sizeof(struct chiron_msg_signal));
			}
			DEBUG(0, "Got chiron_msg_signal");
			status = handle_chiron_msg_signal(ctx, signal);

			break;
		}
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
			DEBUG( 0, "Error when reading packet from fd %d: %s!", ctx->clientfd, strerror(errno));
			return ST_PARSE_ERROR;
		} else if (n == sizeof(buf)) {
			DEBUG(0, "Maximum packet size exceeded!");
			return ST_PARSE_ERROR;
		}

		/* Copy packet to data blob */
		data.length = n;
		data.data = talloc_memdup(ctx, buf, n);
		NO_MEM_RETURN(data.data);

		STATUS status = handle_message(ctx, data);
		if (status != ST_OK) {
			DEBUG(0,"Got handle_message status %d", status);
			return status;
		}
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
		if (clientfd < 0) {
			DEBUG(0, "Error on accept: %s", strerror(errno));
			continue;
		}
		getnameinfo((struct sockaddr *)&clientaddr, clientlen,
			    clienthost, sizeof(clienthost),
			    clientservice, sizeof(clientservice),
			    NI_NUMERICHOST | NI_NUMERICSERV);
		DEBUG(3, "Received connection from %s:%s", clienthost, clientservice);

		if (fork()) {
			close(clientfd);
			continue;
		} else {
			struct chiron_context *client_ctx = talloc_zero(mem_ctx, struct chiron_context);
			if (client_ctx == NULL) {
				close(sock);
				close(clientfd);
				DEBUG(0, "Out of memory");
				return ST_OUT_OF_MEMORY;
			}
			client_ctx->clientaddr = (struct sockaddr *)&clientaddr;
			client_ctx->clientfd = clientfd;

			DEBUG(0, "Handling connection for fd %d", clientfd);
			STATUS status = dispatcher(client_ctx);
			DEBUG(0, "Shutting down connection for fd %d", clientfd);

			shutdown(clientfd, SHUT_RDWR);
			close(clientfd);

			talloc_free(client_ctx);
			exit(status);
		}

	}
	shutdown(sock, SHUT_RDWR);
	close(sock);
}

static void sigchld_handler(int sig)
{
	pid_t p;
	int status;

	while ((p = waitpid(-1, &status, WNOHANG)) > 0) {
		DEBUG(0, "Child process %d exited with status %d", p, status);
	}
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
	 * Handle death of children
	 */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sigaction(SIGCHLD, &sa, NULL);

	/*
	 * Open up a TCP socket the Chiron port
	 */
	listen_server(mem_ctx, "::", CHIRON_PORT, "tcp", handle_connection);

	talloc_free(mem_ctx);
	return 0;
}
