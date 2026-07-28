#ifndef __KEYS_H__
#define __KEYS_H__

#include "common.h"

#define EID_ROOT_KEY_SIZE 0x20
#define EID_ROOT_IV_SIZE 0x10

#define MODULE_SEEDS_SIZE 0x40
#define ZERO_IV_SIZE 0x10

#define PAYLOAD_KEY_SIZE 0x10

#define TWEAK_KEY_SIZE 0x10
#define DATA_KEY_SIZE 0x10

#define SESSION_COUNT 8

unsigned char* eid_root_key[EID_ROOT_KEY_SIZE];
unsigned char* eid_root_iv[EID_ROOT_IV_SIZE];
void get_eid_root_key();

const uint8_t module_seeds[MODULE_SEEDS_SIZE];
const uint8_t zero_iv[ZERO_IV_SIZE];

const uint8_t payload_magic[PAYLOAD_MAGIC_SIZE];
const uint8_t payload_empty_string[PAYLOAD_EMPTY_STRING_SIZE];

const uint8_t payload_be2sc_key[PAYLOAD_KEY_SIZE];
const uint8_t payload_sc2be_key[PAYLOAD_KEY_SIZE];

const uint8_t tweak_key_seed[TWEAK_KEY_SIZE];
const uint8_t data_key_seed[DATA_KEY_SIZE];

const uint8_t* const auth_key_seeds[SESSION_COUNT * 2];
const uint8_t* const session_key_seeds[SESSION_COUNT];

#endif
