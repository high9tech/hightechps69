#ifndef __COMMON_H__
#define __COMMON_H__

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define AUTH_KEYGEN_KEY_SIZE 0x20
#define KEYGEN_KEY_SIZE 0x10
#define KEYGEN_IV_SIZE 0x10
#define AUTH_KEY_SIZE 0x10

#define SESSION_KEY_SEED_SIZE 0x10
#define SESSION_KEY_SIZE 0x10

#define RANDOM_CHALLENGE_SIZE 0x10
#define BLOCK_SIZE 0x10

#define PACKET_HEADER_SIZE 0x10

#define PAYLOAD_HEADER_SIZE 0x10
#define PAYLOAD_MAGIC_SIZE 0x2
#define PAYLOAD_NONCE_SIZE 0xB
#define PAYLOAD_DIGEST_SIZE 0x10
#define PAYLOAD_EMPTY_STRING_SIZE 0x10

#define CMD_HEADER_SIZE 0x10
#define CMD_DIGEST_SIZE 0x10

#define GET_STATE_PAYLOAD_SIZE 0x00
#define STATE_SIZE 0x80

#define GET_SYSTEM_INFO_PAYLOAD_SIZE 0x00
#define SYSTEM_INFO_SIZE 0x80

#define QUERY_XDR_CONFIG_PAYLOAD_SIZE 0x02
#define XDR_CONFIG_SIZE 0x80

#define AUTH1_PAYLOAD_SIZE RANDOM_CHALLENGE_SIZE
#define AUTH1_REPLY_PAYLOAD_SIZE (RANDOM_CHALLENGE_SIZE + RANDOM_CHALLENGE_SIZE)

#define AUTH2_PAYLOAD_SIZE RANDOM_CHALLENGE_SIZE
#define AUTH2_REPLY_PAYLOAD_SIZE (RANDOM_CHALLENGE_SIZE + RANDOM_CHALLENGE_SIZE)

#define READ_DATA_CMD_SIZE 0x10
#define READ_DATA_CMD_REPLY_SIZE 0x10

#define VERSION_0x1 0x01
#define NO_SESSION 0xFF

#define PACKET_TYPE_SC2BE 0x00
#define PACKET_TYPE_BE2SC 0xFF

#define SERVICE_ID_0x10 0x10 // PS2 PCI Bus Power On/Off
#define SERVICE_ID_0x11 0x11 // Time Zone Presence, Temperature, Thermal Alert Mode
#define SERVICE_ID_CONFIG 0x12 // Configuration?
#define SERVICE_ID_POWER 0x13 // Power Service
#define SERVICE_ID_NVS 0x14 // Non-Volatile Storage
#define SERVICE_ID_LED_BUZZER 0x16 // LED / Buzzer Service
#define SERVICE_ID_VERSION 0x18 // Version Service
#define SERVICE_ID_TERMINAL 0x20 // Terminal Service
#define SERVICE_ID_0x2D 0x2D
#define SERVICE_ID_AV 0x30 // A/V Service
#define SERVICE_ID_AUTH 0x1F // Authenticated Service
#define SERVICE_ID_INIT 0xFF // Initialization Service

#define PHASE_ID_GET_STATE 0x0
#define PHASE_ID_AUTH1 0x2
#define PHASE_ID_AUTH2 0x3
#define PHASE_ID_SECURE_SERVICE 0x4
#define PHASE_ID_GET_SYSTEM_INFO 0x6
#define PHASE_ID_UNSECURE_SERVICE 0xFF

#define SERVICE_ID_READ_WRITE 0x4

#define PACKET_BUFFER_SIZE 0x10000
#define SECURE_PAYLOAD_BUFFER_SIZE 0x100

#define TIMEOUT 100000

struct __attribute__ ((packed)) pkt_hdr_t {
	uint8_t service_id;
	uint8_t version;
	uint16_t transaction_id;
	uint8_t res[2];
	uint16_t checksum;
	uint32_t communication_tag;
	uint16_t body_size[2];
};

struct __attribute__ ((packed)) pld_hdr_t {
	uint8_t session_id;
	uint8_t phase_id;
	uint8_t packet_type;
	uint8_t magic[PAYLOAD_MAGIC_SIZE];
	uint8_t nonce[PAYLOAD_NONCE_SIZE];
};

// FIXME
struct __attribute__ ((packed)) cmd_hdr_t {
	uint32_t unk1;
	uint32_t index;
	uint8_t seq_service_id;
	uint8_t padding[7];
};

struct __attribute__ ((packed)) get_state_t {
};

struct __attribute__ ((packed)) get_state_reply_t {
	uint8_t state[STATE_SIZE];
};

struct __attribute__ ((packed)) get_system_info_t {
};

struct __attribute__ ((packed)) get_system_info_reply_t {
	uint8_t system_info[SYSTEM_INFO_SIZE];
};

struct __attribute__ ((packed)) auth1_t {
	uint8_t host_challenge[RANDOM_CHALLENGE_SIZE];
};

struct __attribute__ ((packed)) auth1_reply_t {
	uint8_t host_challenge[RANDOM_CHALLENGE_SIZE];
	uint8_t syscon_challenge[RANDOM_CHALLENGE_SIZE];
};

struct __attribute__ ((packed)) auth2_t {
	uint8_t syscon_challenge[RANDOM_CHALLENGE_SIZE];
};

struct __attribute__ ((packed)) auth2_reply_t {
	uint8_t empty_string[PAYLOAD_EMPTY_STRING_SIZE];
};

struct __attribute__ ((packed)) read_data_cmd_t {
	uint32_t block_index;
	uint32_t block_count;
	uint8_t partition_index;
};

struct __attribute__ ((packed)) read_data_cmd_reply_t {
	uint32_t block_index;
	uint32_t block_count;
	uint8_t partition_index;
	uint8_t padding[7];
	uint8_t data[0];
};

struct __attribute__ ((packed)) cmd_t {
	struct cmd_hdr_t cmd_hdr;

	union {
		struct read_data_cmd_t read;
		struct read_data_cmd_reply_t read_reply;
		uint8_t buf[0];
	};
};

struct __attribute__ ((packed)) pkt_t {
	struct pkt_hdr_t pkt_hdr;

	union {
		struct {
			struct pld_hdr_t pld_hdr;
			union {
				struct get_state_t get_state;
				struct get_state_reply_t get_state_reply;
				struct get_system_info_t get_system_info;
				struct get_system_info_reply_t get_system_info_reply;
				struct auth1_t auth1;
				struct auth1_reply_t auth1_reply;
				struct auth2_t auth2;
				struct auth2_reply_t auth2_reply;
				struct cmd_t cmd;
				uint8_t buf[0];
			} pld;
		};
		uint8_t buf[0];
	};
};

struct __attribute__ ((packed)) pkt_get_hw_config_request_t {
	uint8_t unk1;
};

struct __attribute__ ((packed)) pkt_get_rtc_request_t {
	uint8_t unk1;
};

struct __attribute__ ((packed)) pkt_get_rtc_response_t {
	uint64_t rtc;
};

struct __attribute__ ((packed)) pkt_query_xdr_config_request_t {
	uint8_t unk1;
	uint8_t unk2;
};

struct __attribute__ ((packed)) pkt_query_xdr_config_response_t {
	uint8_t data[XDR_CONFIG_SIZE];
};

struct __attribute__ ((packed)) pkt_get_version_request_t {
	uint8_t cmd; // 0x01
	uint8_t service_id;
};

struct __attribute__ ((packed)) pkt_get_version_response_t {
	uint8_t status;
	uint8_t service_id;
	uint16_t version;
};

/*struct __attribute__ ((packed)) pkt_get_syscon_version_request_t {
	uint8_t cmd; // 0x12/0x14
};

struct __attribute__ ((packed)) pkt_get_syscon_version_response_t {
	uint8_t status;
	uint8_t padding[3];
	uint16_t version;
};*/

struct __attribute__ ((packed)) pkt_ring_buzzer_request_t {
	uint8_t res1;
	uint8_t field1;
	uint8_t field2;
	uint8_t res2;
	uint32_t field4;
};

struct __attribute__ ((packed)) pkt_shutdown_request_t {
	uint8_t unk1;
};

enum {
	NVS_WRITE = 0x10,
	NVS_READ = 0x20,
};

struct __attribute__ ((packed)) pkt_nvs_request_t {
	uint8_t cmd;
	uint8_t block;
	uint8_t offset;
	uint8_t length;
};

void dump_data(const void* data, uint64_t size);

static inline uint32_t align_up(uint32_t x, uint32_t alignment) {
	return (x + (alignment - 1)) & ~(alignment - 1);
}

#endif
