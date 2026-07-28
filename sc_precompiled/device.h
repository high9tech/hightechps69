#ifndef __DEVICE_H__
#define __DEVICE_H__

#include "common.h"

int sc_startup(void);
void sc_shutdown(void);

int sc_get(void* const data, uint32_t* const data_size);
int sc_put(const void* const data, const uint32_t buffer_size);

uint16_t sc_calc_hdr_cksum(void* const data);
uint16_t sc_calc_pkt_cksum(const void* const data, const uint32_t size);

int sc_get_hw_config(void);
int sc_query_xdr_config(uint8_t arg1, uint8_t arg2, uint8_t data[XDR_CONFIG_SIZE]);

int sc_get_version(uint8_t arg, uint16_t* version);
//int sc_get_syscon_version(uint16_t* version);
int sc_get_rtc(uint64_t* rtc);

enum {
	BEEP_SINGLE = 0,
	BEEP_DOUBLE,
	BEEP_CONTINUOUS,
};

int sc_beep(int type);

int sc_be_shutdown(void);

int sc_nvs_read(uint32_t block, uint32_t offset, uint32_t length);

#endif