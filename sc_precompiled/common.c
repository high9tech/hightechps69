#include "common.h"

void dump_data(const void* data, uint64_t size) {
	const uint8_t* ptr = (const uint8_t*)data;
	uint64_t i;
	for (i = 0; i < size; ++i) {
		if ((!(i % 16)) & (i != 0))
			fprintf(stdout, "\n");
		fprintf(stdout, "%02X ", *ptr++);
	}
	fprintf(stdout, "\n");
}
