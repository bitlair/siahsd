#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


/* Libs */
#include <talloc.h>
#include <dbi/dbi.h>
#include <glib.h>

/* Private */
#include "siahsd.h"
#include "siahs.h"
#include "sia.h"

#define MY_DEVICE "RCIPv2.4"

#define CONFIGFILE "/etc/siahsd.conf"

/* TODO:
 * - Add event connection to jsonbot
 * - Keep PROM state and monitor keepalives
 * - Make a load balancer that balances REGISTRATION REQUESTS to the proper port
 */


/* My global state */
configuration *conf = NULL;
const char *process_name = NULL;

STATUS debug(int loglevel, const char *location, const char *function, ...)
{
	va_list ap;
	static char timebuf[100]; /* Static because this should not be reallocated 
	                             in case of out of memory errors */
	time_t rawtime;
	struct tm *timeinfo;
	size_t s;
	FILE *logfile;

	if (loglevel > conf->log_level) {
		return ST_OK;
	}

	logfile = fopen(conf->log_file, "a");
	if (logfile == NULL && conf->foreground) {
		fprintf(stderr, "Error opening log file: %s\n", strerror(errno));
	}

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	
	s = strftime(timebuf, sizeof(timebuf), "%c", timeinfo);
	if (s == 0) {
		const char *text = "Failed to get proper strftime formatted date\n";
		if (conf->foreground) {
			fprintf(stderr, text);
		}
		fprintf(logfile, text);
		return ST_GENERAL_FAILURE;
	}

	fprintf(logfile, "%s: %s(%d): Log level %d, at %s in function %s():\n", 
	                 timebuf, process_name, getpid(), loglevel, location, function);
	if (conf->foreground)
		fprintf(stderr, "%s: %s(%d): Log level %d, at %s in function %s():\n", 
		                timebuf, process_name, getpid(), loglevel, location, function);

	va_start(ap, function);
	vfprintf(logfile, va_arg(ap, char *), ap);
	va_end(ap);
	fputc('\n', logfile);

	if (conf->foreground) {
		va_start(ap, function);
		vfprintf(stderr, va_arg(ap, char *), ap);
		va_end(ap);
		fputc('\n', stderr);
	}

	fclose(logfile);

	return ST_OK;
}

/*
 * talloc_quoted_string escapes quotes in a string and encapsulates it in quotes.
 * It returns a pointer to talloc'ed memory, the quoted string.
 */
char *talloc_quoted_string(TALLOC_CTX *mem_ctx, const char *string) {
	/* Allocate twice the string length, to be safe and not having to realloc all the time */
	char *ret = talloc_zero_array(mem_ctx, char, strlen(string) * 2 + 1);
	size_t i, j;

	NO_MEM_RETURN_RV(ret, NULL);

	ret[0] = '\'';

	for (i = 0, j = 1; i < strlen(string); i++, j++) {
		if (string[i] == '\'' || string[i] == '\\') {
			ret[j] = '\'';
			ret[++j] = string[i];
		} else {
			ret[j] = string[i];
		}
	}
	ret[j] = '\'';
	ret[++j]  = '\0';

	return ret;
}

/*
 * parse_message parses the string portion of the SIA-HS message
 * and writes the event to the database.
 * It returns nothing.
 */
STATUS parse_message(TALLOC_CTX *mem_ctx, dbi_conn conn, struct packet *pkt) {
	char *message = talloc_strdup(mem_ctx, pkt->message + strlen("MESSAGE "));
	char *ptr = message;
	char *prom = ptr;
	char *pkt_prom;
	char *code;
	char *quoted_prom;
	char *quoted_code;
	char *quoted_long_code;
	char *quoted_description;

	NO_MEM_RETURN(message);

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

	/* The remaining ptr contains the human readable description string */

	
	/* Ignore alive! messages */
	if (strcmp(code, "alive!") == 0) {
		DEBUG(2, "Got keepalive packet from prom %x", prom);
		/* FIXME We must update some keepalive status somewhere to generate offline messages */
		return ST_OK;
	}

	/* Assert that string prom is identical to hex representation of pkt->prom */
	pkt_prom = talloc_asprintf(message, "%04x", pkt->prom);

	NO_MEM_RETURN(pkt_prom);

	if (strcmp(pkt_prom, prom) != 0) {
		return ST_ASSERTION_FAILED;
	}

	quoted_prom = talloc_quoted_string(message, prom);
	quoted_code = talloc_quoted_string(message, code);
	quoted_long_code = talloc_quoted_string(message, sia_code_str(code));
	quoted_description = talloc_quoted_string(message, ptr);

	fprintf(stderr, "%s %s %s -- %s: %s\n", prom, code, ptr, sia_code_str(code), sia_code_desc(code));

	dbi_conn_queryf(conn, "INSERT INTO events (timestamp, prom, code, long_code, description) VALUES (NOW(), %s, %s, %s, %s)\n",
		 quoted_prom, quoted_code, quoted_long_code, quoted_description);

	talloc_free(message);

	return ST_OK;
}


/*
 * send_reply sends a reply to a SIA-HS transmitter
 * It requires a memory context, the socket from which to reply, the socket address to reply to, the original packet
 * and a string with the reply message.
 * It returns nothing.
 */
STATUS send_reply(TALLOC_CTX *mem_ctx, int sock, struct sockaddr_in from, struct packet *pkt, const char *string) {
	int n;
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


	fprintf(stderr, "Sending %s sum %04x len %d\n", string, sum, reply_len - 4);

	n = sendto(sock, reply, reply_len, 0, (struct sockaddr *)&from, sizeof(from));

	/* Cleanup */
	talloc_free(reply);

	return ST_OK;
}

STATUS read_configuration_file(TALLOC_CTX *mem_ctx)
{
	GError *error = NULL;
	GKeyFile *keyfile = g_key_file_new ();

	if (!g_key_file_load_from_file (keyfile, CONFIGFILE, 0, &error)) {
		g_error (error->message);
		return ST_CONFIGURATION_ERROR;
	}

	conf = talloc(mem_ctx, configuration);
	NO_MEM_RETURN(conf);

	conf->database_host = g_key_file_get_string(keyfile, "database",
                                                  "host", &error);
	if (error) {
		fprintf(stderr, "No database host supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_name = g_key_file_get_string(keyfile, "database",
                                                  "name", &error);
	if (error) {
		fprintf(stderr, "No database name supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_driver = g_key_file_get_string(keyfile, "database",
                                                  "driver", &error);
	if (error) {
		fprintf(stderr, "No database driver supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_username = g_key_file_get_string(keyfile, "database",
                                                  "username", &error);
	if (error) {
		fprintf(stderr, "No database username supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->database_password = g_key_file_get_string(keyfile, "database",
                                                  "password", &error);
	if (error) {
		fprintf(stderr, "No database password supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}

	conf->siahs_port = g_key_file_get_integer(keyfile, "siahs", "port", &error);
	if (error) {
		fprintf(stderr, "No SIA-HS port supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->log_file = g_key_file_get_string(keyfile, "siahsd", "log file", &error);
	if (error) {
		fprintf(stderr, "No log file supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->log_level = g_key_file_get_integer(keyfile, "siahsd", "log level", &error);
	if (error) {
		fprintf(stderr, "No log level supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->pid_file = g_key_file_get_string(keyfile, "siahsd", "pid file", &error);
	if (error) {
		fprintf(stderr, "No pid file supplied in the configuration.\n");
		return ST_CONFIGURATION_ERROR;
	}
	conf->foreground = g_key_file_get_boolean(keyfile, "siahsd", "foreground", &error);
	if (error) {
		conf->foreground = false;
	}

	return ST_OK;
}

STATUS connect_to_database(dbi_conn *conn)
{
	DEBUG(1, "Connecting to %s database %s at %s as user %s", conf->database_driver, 
		conf->database_name, conf->database_host, conf->database_username);

	dbi_initialize(NULL);
	*conn = dbi_conn_new(conf->database_driver);
	dbi_conn_set_option(*conn, "host", conf->database_host);
	dbi_conn_set_option(*conn, "username", conf->database_username);
	dbi_conn_set_option(*conn, "password", conf->database_password);
	dbi_conn_set_option(*conn, "dbname", conf->database_name);
	dbi_conn_set_option(*conn, "encoding", "UTF-8");

	if (dbi_conn_connect(*conn) < 0) {
		DEBUG(0, "Could not connect to the database");
		return ST_DATABASE_FAILURE;
	} 

	return ST_OK;
}


int main(int argc, char **argv) {
	int sock, n, i;
	socklen_t fromlen;
	struct sockaddr_in server;
	struct sockaddr_in from;
	TALLOC_CTX *mem_ctx;
	dbi_conn conn;
	STATUS rv;
	FILE *pidfile;
	pid_t pid;

	process_name = argv[0];

	/* Initialize a memory context */
	mem_ctx = talloc_init("siahsd");


	/* Read the configuration file */
	rv = read_configuration_file(mem_ctx);
	if (rv != ST_OK)
		return rv;

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
	         process_name, conf->siahs_port);

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
		struct packet *pkt;
		uint8_t *decoded;
		char buf[1024]; /* Purposefully static length */
		char *reply_message;

		pkt = talloc_zero(mem_ctx, struct packet);

		NO_MEM_RETURN(pkt);

		n = recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &from, &fromlen);
		if (n < 0) {
			DEBUG( 0, "Error when storing packet in buffer!");
			talloc_free(pkt);
			continue;
		} else if (n == sizeof(buf)) {
			DEBUG(0, "Maximum packet size exceeded!");
			talloc_free(pkt);
			continue;
		}
		
		src_port = ntohs(from.sin_port);

		pkt->len = ntohl(*(uint32_t *)buf);

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

			send_reply(pkt, sock, from, pkt, "ACKNOWLEDGE MESSAGE");
			parse_message(pkt, conn, pkt);

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

