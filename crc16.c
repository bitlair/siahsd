#include <stdint.h>

uint16_t calculate_crc (const uint8_t *ptr, uint16_t count) {
	#define CRC16_SEED 0x1021
	uint16_t crc;
	uint8_t i;
	crc = 0;

	while (count-- > 0) {
		crc = crc ^ ((uint16_t) *ptr++ << 8);
		for (i = 0; i < 8; i++) {
			if (crc & 0x8000) {
				crc = crc << 1 ^ CRC16_SEED;
			} else {
				crc = crc << 1;
			}
		}
	}
	return crc;
}
