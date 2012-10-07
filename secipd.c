/*
   Vebon Sec-IP Alarm Monitoring Service
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
#include <nettle/aes.h>

#include "includes.h"
#include "build/ndr_secip.h"
#include "siahs.h"

/* FIXME Does not handle multiple connections.. should be per connection obviously!! */
static uint8_t global_aes_key[16];


static STATUS send_ppk_com(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct secip_packet *pkt) {
	struct secip_setup_packet *setup_pkt;
	struct secip_packet *ppk_com;
	DATA_BLOB raw_pkt, raw_setup_pkt;
	enum ndr_err_code ndr_err;
	size_t n, i;
	size_t count;
	const configuration *conf = get_conf();


	setup_pkt = talloc(mem_ctx, struct secip_setup_packet);

	ppk_com = talloc(setup_pkt, struct secip_packet);
	ppk_com->pad = 0;
	ppk_com->connection_id = 0x1337; /* FIXME */
	ppk_com->message_id = SECIP_MSG_PPK_COM;
	ppk_com->sequence_number = 1;
	ppk_com->msg.ppk_com.session_id = 0;

	/* Device ID must not be readable at this stage */
	for (i = 0; i < 16; i++) {
		ppk_com->device_id[i] = rand();
	}
	for (i = 0; i < 74; i++) {
		ppk_com->msg.ppk_com.padding[i] = rand();
	}

	mpz_export(&ppk_com->msg.ppk_com.rsa_key, &count, -1, 1, -1, 0, conf->public_key->n);
	DEBUG(0, "RSA Words written: %u", count);

	DEBUG(9, "%s", ndr_print_struct_string(pkt,(ndr_print_fn_t)ndr_print_secip_packet, "ppk_com packet", ppk_com));

	ndr_err = ndr_push_struct_blob(&raw_pkt, ppk_com, ppk_com, (ndr_push_flags_fn_t)ndr_push_secip_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}
	
	memcpy(setup_pkt->raw_packet, raw_pkt.data, raw_pkt.length);
	for (i = 0; i < 30; i++) {
		setup_pkt->padding[i] = rand();
	}


	ndr_err = ndr_push_struct_blob(&raw_setup_pkt, setup_pkt, setup_pkt, (ndr_push_flags_fn_t)ndr_push_secip_setup_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}

	n = sendto(sock, raw_setup_pkt.data, raw_setup_pkt.length, 0, (struct sockaddr *)&from, sizeof(from));

	talloc_free(setup_pkt);
	return 0;
}

static STATUS send_arc_enc(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct secip_packet *pkt) {
	struct secip_setup_packet *setup_pkt;
	struct secip_packet *arc_enc;
	DATA_BLOB raw_pkt, raw_setup_pkt, crypted_setup_pkt;
	size_t n, i;
	enum ndr_err_code ndr_err;
	struct aes_ctx aes;

	aes_set_encrypt_key(&aes, 16, pkt->msg.ppk_rep.key_block.aes_key);

	/* FIXME DEATH TO THE GLOBALS! */
	memcpy(global_aes_key, pkt->msg.ppk_rep.key_block.aes_key, 16);

	setup_pkt = talloc(mem_ctx, struct secip_setup_packet);

	arc_enc = talloc_zero(setup_pkt, struct secip_packet);
	arc_enc->pad = 0;
	arc_enc->connection_id = 0x1337; /* FIXME */
	memcpy(arc_enc->device_id, "Bitlair SecIPd!", 16);
	arc_enc->message_id = SECIP_MSG_ARC_ENC;
	arc_enc->sequence_number = 2;

	arc_enc->msg.arc_enc.error_code = SECIP_ERR_SUCCESS;
	arc_enc->msg.arc_enc.session_id = pkt->msg.ppk_com.session_id;
	
	for (i = 0; i < 231; i++) {
		arc_enc->msg.arc_enc.padding[i] = rand();
	}

	DEBUG(9, "%s", ndr_print_struct_string(mem_ctx, (ndr_print_fn_t)ndr_print_secip_packet, "arc_enc packet", arc_enc));

	ndr_err = ndr_push_struct_blob(&raw_pkt, arc_enc, arc_enc, (ndr_push_flags_fn_t)ndr_push_secip_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}
	
	memcpy(setup_pkt->raw_packet, raw_pkt.data, raw_pkt.length);
	for (i = 0; i < 30; i++) {
		setup_pkt->padding[i] = rand();
	}

	ndr_err = ndr_push_struct_blob(&raw_setup_pkt, setup_pkt, setup_pkt, (ndr_push_flags_fn_t)ndr_push_secip_setup_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}

	crypted_setup_pkt.data = talloc_zero_array(mem_ctx, uint8_t, 258);
	crypted_setup_pkt.length = 258;
	memcpy(crypted_setup_pkt.data, raw_setup_pkt.data, 2);

	aes_encrypt(&aes, raw_setup_pkt.length-2, crypted_setup_pkt.data+2, raw_setup_pkt.data+2);

	n = sendto(sock, crypted_setup_pkt.data, crypted_setup_pkt.length, 0, (struct sockaddr *)&from, sizeof(from));

	return ST_OK;
}

static STATUS send_psup_resp(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct secip_packet *pkt) {
	DATA_BLOB raw_pkt, raw_comm_pkt, crypted_comm_pkt;
	struct secip_comm_packet *comm_pkt;
	struct secip_packet *psup_resp;
	enum ndr_err_code ndr_err;
	struct aes_ctx aes;
	int i, n;

	/* FIXME DEATH TO THE GLOBALS! */
	aes_set_encrypt_key(&aes, 16, global_aes_key);

	comm_pkt = talloc(mem_ctx, struct secip_comm_packet);

	psup_resp = talloc_zero(comm_pkt, struct secip_packet);
	psup_resp->pad = 0;
	psup_resp->connection_id = 0x1337; /* FIXME */
	memcpy(psup_resp->device_id, "Bitlair SecIPd!", 16);
	psup_resp->message_id = SECIP_MSG_PATH_SUPERVISION_RESPONSE;
	psup_resp->sequence_number = pkt->sequence_number;

	psup_resp->msg.psup_resp.error_code = SECIP_ERR_SUCCESS; /* FIXME: Make sure we actually supervise */
	psup_resp->msg.psup_resp.path_id = pkt->msg.psup_req.path_id;
	psup_resp->msg.psup_resp.interval_seconds = pkt->msg.psup_req.interval_seconds;
	
	for (i = 0; i < 69; i++) {
		psup_resp->msg.psup_resp.padding[i] = rand();
	}

	DEBUG(9, "%s", ndr_print_struct_string(mem_ctx, (ndr_print_fn_t)ndr_print_secip_packet, "psup_resp packet", psup_resp));

	ndr_err = ndr_push_struct_blob(&raw_pkt, psup_resp, psup_resp, (ndr_push_flags_fn_t)ndr_push_secip_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}
	
	memcpy(comm_pkt->raw_packet, raw_pkt.data, raw_pkt.length);
	for (i = 0; i < 30; i++) {
		comm_pkt->padding[i] = rand();
	}

	ndr_err = ndr_push_struct_blob(&raw_comm_pkt, comm_pkt, comm_pkt, (ndr_push_flags_fn_t)ndr_push_secip_comm_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}

	crypted_comm_pkt.data = talloc_zero_array(mem_ctx, uint8_t, 258);
	crypted_comm_pkt.length = 130;
	memcpy(crypted_comm_pkt.data, raw_comm_pkt.data, 2);

	aes_encrypt(&aes, raw_comm_pkt.length-2, crypted_comm_pkt.data+2, raw_comm_pkt.data+2);

	n = sendto(sock, crypted_comm_pkt.data, crypted_comm_pkt.length, 0, (struct sockaddr *)&from, sizeof(from));

	return ST_OK;
}

static STATUS send_pathcheck_resp(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct secip_packet *pkt) {
	DATA_BLOB raw_pkt, raw_comm_pkt, crypted_comm_pkt;
	struct secip_comm_packet *comm_pkt;
	struct secip_packet *pathcheck_resp;
	enum ndr_err_code ndr_err;
	struct aes_ctx aes;
	int i, n;

	/* FIXME DEATH TO THE GLOBALS! */
	aes_set_encrypt_key(&aes, 16, global_aes_key);


	comm_pkt = talloc(mem_ctx, struct secip_comm_packet);

	pathcheck_resp = talloc_zero(comm_pkt, struct secip_packet);
	pathcheck_resp->pad = 0;
	pathcheck_resp->connection_id = 0x1337; /* FIXME */
	memcpy(pathcheck_resp->device_id, "Bitlair SecIPd!", 16);
	pathcheck_resp->message_id = SECIP_MSG_PATH_SUPERVISION_RESPONSE;
	pathcheck_resp->sequence_number = pkt->sequence_number;

	pathcheck_resp->msg.pathcheck_resp.error_code = SECIP_ERR_PATHCHECK_NOT_SUPPORTED; /* FIXME */
	
	for (i = 0; i < 74; i++) {
		pathcheck_resp->msg.pathcheck_resp.padding[i] = rand();
	}

	DEBUG(9, "%s", ndr_print_struct_string(mem_ctx, (ndr_print_fn_t)ndr_print_secip_packet, "pathcheck_resp packet", pathcheck_resp));

	ndr_err = ndr_push_struct_blob(&raw_pkt, pathcheck_resp, pathcheck_resp, (ndr_push_flags_fn_t)ndr_push_secip_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}
	
	memcpy(comm_pkt->raw_packet, raw_pkt.data, raw_pkt.length);
	for (i = 0; i < 30; i++) {
		comm_pkt->padding[i] = rand();
	}

	ndr_err = ndr_push_struct_blob(&raw_comm_pkt, comm_pkt, comm_pkt, (ndr_push_flags_fn_t)ndr_push_secip_comm_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}

	crypted_comm_pkt.data = talloc_zero_array(mem_ctx, uint8_t, 258);
	crypted_comm_pkt.length = 130;
	memcpy(crypted_comm_pkt.data, raw_comm_pkt.data, 2);

	aes_encrypt(&aes, raw_comm_pkt.length-2, crypted_comm_pkt.data+2, raw_comm_pkt.data+2);

	n = sendto(sock, crypted_comm_pkt.data, crypted_comm_pkt.length, 0, (struct sockaddr *)&from, sizeof(from));

	return ST_OK;
}

static STATUS send_alarm_ack(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct secip_packet *pkt) {
	DATA_BLOB raw_pkt, raw_comm_pkt, crypted_comm_pkt;
	struct secip_comm_packet *comm_pkt;
	struct secip_packet *alarm_ack;
	enum ndr_err_code ndr_err;
	struct aes_ctx aes;
	int i, n;
	char *message;

	/* FIXME DEATH TO THE GLOBALS! */
	aes_set_encrypt_key(&aes, 16, global_aes_key);

	message = talloc_strndup(pkt, (char *)pkt->msg.alarm.message, pkt->msg.alarm.length);
	DEBUG(0, "Got message: %s", message);

	/* FIXME Hardcoded prom */
	parse_siahs_message(pkt, "1337", message);

	comm_pkt = talloc(mem_ctx, struct secip_comm_packet);

	alarm_ack = talloc_zero(comm_pkt, struct secip_packet);
	alarm_ack->pad = 0;
	alarm_ack->connection_id = 0x1337; /* FIXME */
	memcpy(alarm_ack->device_id, "Bitlair SecIPd!", 16);
	alarm_ack->message_id = SECIP_MSG_ALARM_ACKNOWLEDGE;
	alarm_ack->sequence_number = pkt->sequence_number;

	alarm_ack->msg.alarm_ack.error_code = SECIP_ERR_ACKNOWLEDGE;
	
	for (i = 0; i < 75; i++) {
		alarm_ack->msg.alarm_ack.padding[i] = rand();
	}

	DEBUG(9, "%s\n", ndr_print_struct_string(mem_ctx, (ndr_print_fn_t)ndr_print_secip_packet, "alarm_ack packet", alarm_ack));

	ndr_err = ndr_push_struct_blob(&raw_pkt, alarm_ack, alarm_ack, (ndr_push_flags_fn_t)ndr_push_secip_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}
	
	memcpy(comm_pkt->raw_packet, raw_pkt.data, raw_pkt.length);
	for (i = 0; i < 30; i++) {
		comm_pkt->padding[i] = rand();
	}

	ndr_err = ndr_push_struct_blob(&raw_comm_pkt, comm_pkt, comm_pkt, (ndr_push_flags_fn_t)ndr_push_secip_comm_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}

	crypted_comm_pkt.data = talloc_zero_array(mem_ctx, uint8_t, 258);
	crypted_comm_pkt.length = 130;
	memcpy(crypted_comm_pkt.data, raw_comm_pkt.data, 2);

	aes_encrypt(&aes, raw_comm_pkt.length-2, crypted_comm_pkt.data+2, raw_comm_pkt.data+2);

	n = sendto(sock, crypted_comm_pkt.data, crypted_comm_pkt.length, 0, (struct sockaddr *)&from, sizeof(from));

	return ST_OK;
}

static STATUS send_poll_ack(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct secip_packet *pkt) {
	DATA_BLOB raw_pkt, raw_comm_pkt, crypted_comm_pkt;
	struct secip_comm_packet *comm_pkt;
	struct secip_packet *poll_ack;
	enum ndr_err_code ndr_err;
	struct aes_ctx aes;
	int i, n;

	/* FIXME DEATH TO THE GLOBALS! */
	aes_set_encrypt_key(&aes, 16, global_aes_key);


	comm_pkt = talloc(mem_ctx, struct secip_comm_packet);

	poll_ack = talloc_zero(comm_pkt, struct secip_packet);
	poll_ack->pad = 0;
	poll_ack->connection_id = 0x1337; /* FIXME */
	memcpy(poll_ack->device_id, "Bitlair SecIPd!", 16);
	poll_ack->message_id = SECIP_MSG_PATH_SUPERVISION_RESPONSE;
	poll_ack->sequence_number = pkt->sequence_number;

	poll_ack->msg.pathcheck_resp.error_code = SECIP_ERR_SUCCESS; /* FIXME */
	
	for (i = 0; i < 73; i++) {
		poll_ack->msg.poll_ack.padding[i] = rand();
	}

	DEBUG(9, "%s", ndr_print_struct_string(mem_ctx, (ndr_print_fn_t)ndr_print_secip_packet, "poll_ack packet", poll_ack));

	ndr_err = ndr_push_struct_blob(&raw_pkt, poll_ack, poll_ack, (ndr_push_flags_fn_t)ndr_push_secip_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}
	
	memcpy(comm_pkt->raw_packet, raw_pkt.data, raw_pkt.length);
	for (i = 0; i < 30; i++) {
		comm_pkt->padding[i] = rand();
	}

	ndr_err = ndr_push_struct_blob(&raw_comm_pkt, comm_pkt, comm_pkt, (ndr_push_flags_fn_t)ndr_push_secip_comm_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!");
		return ST_GENERAL_FAILURE;
	}

	crypted_comm_pkt.data = talloc_zero_array(mem_ctx, uint8_t, 258);
	crypted_comm_pkt.length = 130;
	memcpy(crypted_comm_pkt.data, raw_comm_pkt.data, 2);

	aes_encrypt(&aes, raw_comm_pkt.length-2, crypted_comm_pkt.data+2, raw_comm_pkt.data+2);

	n = sendto(sock, crypted_comm_pkt.data, crypted_comm_pkt.length, 0, (struct sockaddr *)&from, sizeof(from));

	return ST_OK;
}

static DATA_BLOB decrypt_setup_packet(TALLOC_CTX *mem_ctx, DATA_BLOB encrypted_blob) {
	const configuration *conf = get_conf();
	mpz_t encrypted_data;
	mpz_t decrypted_data;
	DATA_BLOB decrypted_blob;
	int pos;
	size_t length = 1;

	decrypted_blob.length = 258;
	decrypted_blob.data = talloc_zero_array(mem_ctx, uint8_t, 258);
	memcpy(decrypted_blob.data, encrypted_blob.data, 0x02);


	for (pos = 0x02; pos < 258; pos += 128) {
		/* Initialize the big numbers */
		mpz_init(encrypted_data);
		mpz_init(decrypted_data);

		/* Do not decrypt the CRC and the connection ID */
		mpz_import(encrypted_data, 1, 1, 128, 1, 0, encrypted_blob.data + pos);

		rsa_compute_root(conf->private_key, decrypted_data, encrypted_data);

		mpz_export(decrypted_blob.data + pos, &length, 1, 128, 1, 0, decrypted_data);
	}

	
	return decrypted_blob;
}

static DATA_BLOB decrypt_aes_packet(TALLOC_CTX *mem_ctx, DATA_BLOB encrypted_blob) {
	static DATA_BLOB ret;
	struct aes_ctx aes;


	ret.length = encrypted_blob.length;
	ret.data = talloc_zero_array(mem_ctx, uint8_t, ret.length);
	memcpy(ret.data, encrypted_blob.data, 2);

	aes_set_decrypt_key(&aes, 16, global_aes_key);

	aes_decrypt(&aes, encrypted_blob.length-2, ret.data+2, encrypted_blob.data+2);

	DEBUG(0, "Decrypted this packet maybe!");
	return ret;
}


int main (int argc, char **argv) {
	int sock, n;
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

	read_rsa_keys();

	DEBUG(0, "Started %s and waiting for SecIP packets on port %d", 
	         get_process_name(), conf->secip_port);

	/*
	 * Wait for packets
	 */

	fromlen = sizeof(struct sockaddr_in);
	while (1) {
		uint16_t src_port;
		struct secip_setup_packet *setup_pkt;
		struct secip_comm_packet *comm_pkt;
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
		DEBUG(3, "Received packet with len %d from %u", n, src_port);

		/* Copy packet to data blob */
		data.length = n;
		data.data = talloc_memdup(pkt, buf, n);
		
		if (*(uint16_t *)data.data < 0xFF00 && data.length > 256) {
			data = decrypt_setup_packet(pkt, data);
			if (data.length == 0) {
				DEBUG(0, "RSA decryption failed, freeing up memory");
				talloc_free(pkt);
				continue;
			}
		} else if (*(uint16_t *)data.data < 0xFF00 && data.length > 128) {
			data = decrypt_aes_packet(pkt, data);
			if (data.length == 0) {
				DEBUG(0, "AES decryption failed, freeing up memory");
				talloc_free(pkt);
				continue;
			}
		}

		/* Parse the header */
		if (data.length > 256) {
			setup_pkt = talloc(pkt, struct secip_setup_packet);
			ndr_err = ndr_pull_struct_blob_all(&data, pkt, setup_pkt, (ndr_pull_flags_fn_t)ndr_pull_secip_setup_packet);

			if (ndr_err != NDR_ERR_SUCCESS) {
				DEBUG(0, "Could not parse this CRC packet");
			}
			DEBUG(10, "%s", ndr_print_struct_string(setup_pkt,(ndr_print_fn_t)ndr_print_secip_setup_packet, "setup packet", setup_pkt));
		} else if (data.length > 128) {
			comm_pkt = talloc(pkt, struct secip_comm_packet);
			ndr_err = ndr_pull_struct_blob_all(&data, pkt, comm_pkt, (ndr_pull_flags_fn_t)ndr_pull_secip_comm_packet);

			if (ndr_err != NDR_ERR_SUCCESS) {
				DEBUG(0, "Could not parse this CRC packet");
			}
			DEBUG(10, "%s", ndr_print_struct_string(comm_pkt,(ndr_print_fn_t)ndr_print_secip_comm_packet, "comm packet", comm_pkt));
		}

		ndr_err = ndr_pull_struct_blob_all(&data, pkt, pkt, (ndr_pull_flags_fn_t)ndr_pull_secip_packet);

		if (ndr_err != NDR_ERR_SUCCESS) {
			DEBUG(0, "Could not parse this packet");
		}
		DEBUG(9, "%s", ndr_print_struct_string(pkt,(ndr_print_fn_t)ndr_print_secip_packet, "packet", pkt));

		DEBUG(0, "%x %x %x", pkt->connection_id, pkt->message_id, pkt->sequence_number);

		if (pkt->message_id == SECIP_MSG_ATE_ENC && pkt->msg.ate_enc.session_id == 0x0000) {
			send_ppk_com(pkt, sock, from, pkt);
		} else if (pkt->message_id == SECIP_MSG_PPK_REP) {
			send_arc_enc(pkt, sock, from, pkt);
		} else if (pkt->message_id == SECIP_MSG_PATH_SUPERVISION_REQUEST) {
			send_psup_resp(pkt, sock, from, pkt);
		} else if (pkt->message_id == SECIP_MSG_PATH_CHECK_REQUEST) {
			send_pathcheck_resp(pkt, sock, from, pkt);
		} else if (pkt->message_id == SECIP_MSG_ALARM) {
			send_alarm_ack(pkt, sock, from, pkt);
		} else if (pkt->message_id == SECIP_MSG_POLL_MESSAGE) {
			send_poll_ack(pkt, sock, from, pkt);
		}


		talloc_free(pkt);
	}
}
