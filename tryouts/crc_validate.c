#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "packets.h"


char *bin(uint16_t x)
{
    char *b = malloc(17);
    b[0] = '\0';

    uint16_t z;
    for (z = 1 << 15; z > 0; z >>= 1) {
        strcat(b, (x & z) ? "1" : "0");
    }

    return b;
}


void create_packet_array(const uint8_t *packets[2][40])
{
	packets[0][0] = peer0_0;
	packets[0][1] = peer0_1;
	packets[0][2] = peer0_2;
	packets[0][3] = peer0_3;
	packets[0][4] = peer0_4;
	packets[0][5] = peer0_5;
	packets[0][6] = peer0_6;
	packets[0][7] = peer0_7;
	packets[0][8] = peer0_8;
	packets[0][9] = peer0_9;
	packets[0][10] = peer0_10;
	packets[0][11] = peer0_11;
	packets[0][12] = peer0_12;
	packets[0][13] = peer0_13;
	packets[0][14] = peer0_14;
	packets[0][15] = peer0_15;
	packets[0][16] = peer0_16;
	packets[0][17] = peer0_17;
	packets[0][18] = peer0_18;
	packets[0][19] = peer0_19;
	packets[0][20] = peer0_20;
	packets[0][21] = peer0_21;
	packets[0][22] = peer0_22;
	packets[0][23] = peer0_23;
	packets[0][24] = peer0_24;
	packets[0][25] = peer0_25;
	packets[0][26] = peer0_26;
	packets[0][27] = peer0_27;
	packets[0][28] = peer0_28;
	packets[0][29] = peer0_29;
	packets[0][30] = peer0_30;
	packets[0][31] = peer0_31;
	packets[0][32] = peer0_32;
	packets[0][33] = peer0_33;
	packets[0][34] = peer0_34;
	packets[0][35] = peer0_35;
	packets[0][36] = peer0_36;
	packets[0][37] = peer0_37;
	packets[0][38] = peer0_38;
	packets[0][39] = peer0_39;
	packets[1][0] = peer1_0;
	packets[1][1] = peer1_1;
	packets[1][2] = peer1_2;
	packets[1][3] = peer1_3;
	packets[1][4] = peer1_4;
	packets[1][5] = peer1_5;
	packets[1][6] = peer1_6;
	packets[1][7] = peer1_7;
	packets[1][8] = peer1_8;
	packets[1][9] = peer1_9;
	packets[1][10] = peer1_10;
	packets[1][11] = peer1_11;
	packets[1][12] = peer1_12;
	packets[1][13] = peer1_13;
	packets[1][14] = peer1_14;
	packets[1][15] = peer1_15;
	packets[1][16] = peer1_16;
	packets[1][17] = peer1_17;
	packets[1][18] = peer1_18;
	packets[1][19] = peer1_19;
	packets[1][20] = peer1_20;
	packets[1][21] = peer1_21;
	packets[1][22] = peer1_22;
	packets[1][23] = peer1_23;
	packets[1][24] = peer1_24;
	packets[1][25] = peer1_25;
	packets[1][26] = peer1_26;
	packets[1][27] = peer1_27;
	packets[1][28] = peer1_28;
	packets[1][29] = peer1_29;
	packets[1][30] = peer1_30;
	packets[1][31] = peer1_31;
	packets[1][32] = peer1_32;
	packets[1][33] = peer1_33;
	packets[1][34] = peer1_34;
	packets[1][35] = peer1_35;
	packets[1][36] = peer1_36;
	packets[1][37] = peer1_37;
	packets[1][38] = peer1_38;
	packets[1][39] = peer1_39;
}

#define POLYNOMIAL 0x3FF0


#define WIDTH (16)
#define TOPBIT (1 << (WIDTH - 1))

uint16_t
crcSlow(uint8_t const message[], int nBytes)
{
	uint16_t remainder = 0x10d0; 
	int byte;
	uint8_t bit;

	for (byte = 0; byte < nBytes; ++byte) {
		remainder ^= message[byte];
		for (bit = 0; bit < 8; bit++) {
			if (remainder & 1) {
				remainder = ((remainder >> 1) ^ POLYNOMIAL);
			} else {
				remainder = (remainder >> 1);
			}
		}
	}

	return (remainder);

} /* crcSlow() */



int main (int argc, char **argv)
{
	int i,j;
	const uint8_t *pkts[2][40];
	uint8_t decode_xor;

	create_packet_array(pkts);

	for (j = 0; j < 40; j++) {


		for (i = 0; i < 2; i++) {
			if (i == 0)
				decode_xor = 0xB6;
			else
				decode_xor = 0x85;
			uint32_t len = ntohl(*(uint32_t*) pkts[i][j]);
			uint8_t decoded[len - 5];
			uint16_t crc, calc_crc, nondecoded_crc;
			uint32_t k;
			uint16_t sum = 0;

			len = ntohl(*(uint32_t*) pkts[i][j]);

			decoded[sizeof(decoded)-1] = '\0';
			for (k = 0; k < len-6; k++) {
				decoded[k] = pkts[i][j][k + 8] ^ decode_xor;
			}
			printf("%s\n", decoded+26);

			for (k = 0; k < len+2; k++) {
				sum += pkts[i][j][k];
			}
			crc = ntohs(*(uint16_t*)&decoded[len - 6]);
			calc_crc = crcSlow(decoded, len - 6);


			nondecoded_crc = ntohs(*(uint16_t*)&pkts[i][j][len+2]);
			printf("%04x %04x peer %d len %x\n", 
					nondecoded_crc, sum, i, len);
		}
	}

	return 0;
}

