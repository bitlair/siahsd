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
#include "build/ndr_secip.h"

static int read_rsa_keys(void) {
	int res;
	FILE *file;
	uint8_t buf[1024];
	struct rsa_private_key *priv;
	struct rsa_public_key *pub;
	configuration *conf = get_conf();
	uint8_t *buffer = NULL;
	size_t n, size=0;

	priv = talloc(conf, struct rsa_private_key);
	pub = talloc(conf, struct rsa_public_key);

	rsa_public_key_init (pub);
	rsa_private_key_init (priv);

	file = fopen(conf->rsa_key_file, "r");
	if (file == NULL) {
		DEBUG(0, "Can't open configured rsa key file: %s", conf->rsa_key_file);
		exit(ST_CONFIGURATION_ERROR);
	}

	while (1) {
		n = fread(&buf, 1, 1024, file);
		buffer = talloc_realloc(conf, buffer, uint8_t, size + n);
		memcpy(buffer + size, buf, n);
		size += n;
		if (n < 1024)
			break;
	}

	fclose(file);

	res = rsa_keypair_from_sexp(pub, priv, 0, size, buffer);

	set_rsa_keys(pub, priv);

	return res;
}

STATUS send_ppk_com(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct secip_packet *pkt) {
	struct secip_setup_packet *setup_pkt;
	struct secip_out_packet *ppk_com;
	DATA_BLOB raw_pkt, raw_setup_pkt;
	enum ndr_err_code ndr_err;
	size_t n;
	struct rsa_private_key *priv;
	struct rsa_public_key *pub;
	size_t count;


	setup_pkt = talloc_zero(mem_ctx, struct secip_setup_packet);

	ppk_com = talloc_zero(setup_pkt, struct secip_out_packet);
	ppk_com->connection_id = pkt->connection_id;
	ppk_com->message_id = SECIP_MSG_PPK_COM;
	ppk_com->sequence_number = 1;
	memcpy(ppk_com->device_id, "MyFirstAlarm[TM]", strlen("MyFirstAlarm[TM]"));
	ppk_com->msg.ppk_com.session_id = 0;

	get_rsa_keys(&pub, &priv);

	mpz_export(&ppk_com->msg.ppk_com.rsa_key, &count, 1, 4, 1, 0, pub->n);
	DEBUG(0, "RSA Words written: %u", count);

	printf("%s\n", ndr_print_struct_string(pkt,(ndr_print_fn_t)ndr_print_secip_out_packet, "ppk_com packet", ppk_com));

	ndr_err = ndr_push_struct_blob(&raw_pkt, ppk_com, ppk_com, (ndr_push_flags_fn_t)ndr_push_secip_out_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!\n");
		return ST_GENERAL_FAILURE;
	}
	
	memcpy(setup_pkt->raw_packet, raw_pkt.data, raw_pkt.length);


	ndr_err = ndr_push_struct_blob(&raw_setup_pkt, setup_pkt, setup_pkt, (ndr_push_flags_fn_t)ndr_push_secip_setup_packet);

	if (ndr_err != NDR_ERR_SUCCESS) {
		DEBUG(0, "Oh holy shitstorm! That didn't work!\n");
		return ST_GENERAL_FAILURE;
	}

	n = sendto(sock, raw_setup_pkt.data, raw_setup_pkt.length, 0, (struct sockaddr *)&from, sizeof(from));


	talloc_free(setup_pkt);
	return 0;
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

	read_rsa_keys();

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
		struct secip_setup_packet *setup_pkt;
		struct secip_packet *pkt;
		char buf[1024]; /* Purposefully static length */
		enum ndr_err_code ndr_err;
		DATA_BLOB data;

		setup_pkt = talloc(mem_ctx, struct secip_setup_packet);
		pkt = talloc(setup_pkt, struct secip_packet);

		n = recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &from, &fromlen);
		if (n < 0) {
			DEBUG( 0, "Error when storing packet in buffer!");
			continue;
		} else if (n == sizeof(buf)) {
			DEBUG(0, "Maximum packet size exceeded!");
			continue;
		}
		src_port = ntohs(from.sin_port);

		/* Copy packet to data blob */
		data.length = n;
		data.data = talloc_memdup(setup_pkt, buf, n);
		
		/* Parse the header */
		ndr_err = ndr_pull_struct_blob_all(&data, setup_pkt, setup_pkt, (ndr_pull_flags_fn_t)ndr_pull_secip_setup_packet);

		if (ndr_err != NDR_ERR_SUCCESS) {
			DEBUG(0, "Could not parse this CRC packet");
		}
		printf("%s\n", ndr_print_struct_string(setup_pkt,(ndr_print_fn_t)ndr_print_secip_setup_packet, "setup packet", setup_pkt));

		/* Copy packet to data blob */
		data.length = data.length - sizeof(uint16_t);
		data.data = talloc_memdup(pkt, buf, n);

		ndr_err = ndr_pull_struct_blob_all(&data, pkt, pkt, (ndr_pull_flags_fn_t)ndr_pull_secip_packet);

		if (ndr_err != NDR_ERR_SUCCESS) {
			DEBUG(0, "Could not parse this packet");
		}
		printf("%s\n", ndr_print_struct_string(pkt,(ndr_print_fn_t)ndr_print_secip_packet, "packet", pkt));

		DEBUG(0, "%x %x %x %x", pkt->connection_id, pkt->message_id, pkt->sequence_number);
		if (pkt->message_id == SECIP_MSG_ATE_ENC && pkt->msg.ate_enc.session_id == 0x0000) {
			send_ppk_com(pkt, sock, from, pkt);
		}
		DEBUG(3, "Received packet with len %d from %u", n, src_port);

		talloc_free(setup_pkt);
	}
}
