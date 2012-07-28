
struct packet {
	uint32_t len;
	char unknown1; /* 0x01 */
	char unknown2; /* 0x01 */
	uint16_t unknown3; /* '0xcfff' big endian */

	/* From this point XOR encoded with either 0xB6 or 0x85 */
	char *device;
	uint16_t prom;
	uint8_t unknown4; /* 0x01 */
	uint8_t unknown5; /* 0x2C */
	uint8_t unknown6; /* 0x01 */
	char *message;
	uint16_t checksum;
};


