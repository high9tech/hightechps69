#include "common.h"
#include "device.h"
#include "keys.h"
#include "crypto.h"

uint8_t auth1_key[AUTH_KEY_SIZE];
uint8_t auth2_key[AUTH_KEY_SIZE];

uint8_t auth_keygen_key[AUTH_KEYGEN_KEY_SIZE];
uint8_t keygen_key[KEYGEN_KEY_SIZE];
uint8_t keygen_iv[KEYGEN_IV_SIZE];

uint8_t session_key[SESSION_KEY_SIZE];
uint8_t tweak_key[TWEAK_KEY_SIZE];
uint8_t data_key[DATA_KEY_SIZE];

uint8_t packet_buffer[PACKET_BUFFER_SIZE];

static void generate_user_keys(void) {
	uint8_t user_keys[MODULE_SEEDS_SIZE];
	aes_encrypt_cbc(eid_root_key, EID_ROOT_KEY_SIZE * 8, eid_root_iv, module_seeds, user_keys, MODULE_SEEDS_SIZE);

	memcpy(auth_keygen_key, user_keys + 0x20, AUTH_KEYGEN_KEY_SIZE);
	memcpy(keygen_key, user_keys + 0x20, KEYGEN_KEY_SIZE);
	memcpy(keygen_iv, user_keys + 0x10, KEYGEN_IV_SIZE);
}

static void generate_auth_key(const uint8_t* const seed, uint8_t* const key) {
	aes_encrypt_cbc(auth_keygen_key, AUTH_KEYGEN_KEY_SIZE * 8, zero_iv, seed, key, AUTH_KEY_SIZE);
}

static int generate_auth_keys(const uint32_t session_id) {
	if (session_id >= SESSION_COUNT)
		return -1;

	generate_auth_key(auth_key_seeds[session_id * 2 + 0], auth1_key);
	generate_auth_key(auth_key_seeds[session_id * 2 + 1], auth2_key);

	return 0;
}

static void generate_xts_keys(void) {
	aes_encrypt_cbc(keygen_key, KEYGEN_KEY_SIZE * 8, keygen_iv, tweak_key_seed, tweak_key, TWEAK_KEY_SIZE);
	aes_encrypt_cbc(keygen_key, KEYGEN_KEY_SIZE * 8, keygen_iv, data_key_seed, data_key, DATA_KEY_SIZE);
}

static int setup_packet(struct pkt_hdr_t* const hdr, const uint8_t service_id, const uint8_t version, const uint16_t transaction_id, const uint16_t body_size) {
	// TODO: size check

	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = service_id;
	hdr->version = version;
	hdr->transaction_id = transaction_id;
	hdr->body_size[0] = body_size;
	hdr->body_size[1] = body_size;
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	return 0;
}

static int setup_payload(struct pkt_t* const pkt, const uint8_t session_id, const uint8_t phase_id, const uint32_t length) {
	struct pld_hdr_t* hdr = &pkt->pld_hdr;
	memset(hdr, 0, sizeof(struct pld_hdr_t));
	hdr->session_id = session_id;
	hdr->phase_id = phase_id;
	hdr->packet_type = PACKET_TYPE_BE2SC;
	memcpy(hdr->magic, payload_magic, PAYLOAD_MAGIC_SIZE);
	generate_random_bytes(hdr->nonce, PAYLOAD_NONCE_SIZE);

	aes_encrypt_cbc(payload_be2sc_key, PAYLOAD_KEY_SIZE * 8, zero_iv, pkt->buf, pkt->buf, PAYLOAD_HEADER_SIZE + length);
	aes_cmac(payload_be2sc_key, PAYLOAD_KEY_SIZE * 8, pkt->buf, pkt->buf + PAYLOAD_HEADER_SIZE + length, PAYLOAD_HEADER_SIZE + length);

	return 0;
}

static int setup_encrypted_command(struct pkt_t* pkt, const uint32_t session_id, const uint8_t seq_service_id, const uint8_t session_key[SESSION_KEY_SIZE], const uint32_t data_length) {
	struct cmd_t* cmd = &pkt->pld.cmd;

	// TODO: fill header
	struct cmd_hdr_t* hdr = &cmd->cmd_hdr;
	memset(hdr, 0, sizeof(struct cmd_hdr_t));
	hdr->seq_service_id = seq_service_id;
	hdr->index = 1;

	fprintf(stdout, "CMD:\n");
	dump_data(pkt->pld.buf, CMD_HEADER_SIZE + data_length);

	aes_encrypt_cbc(session_key, SESSION_KEY_SIZE * 8, zero_iv, pkt->pld.buf, pkt->pld.buf, CMD_HEADER_SIZE + data_length);
	aes_cmac(session_key, SESSION_KEY_SIZE * 8, pkt->pld.buf, pkt->pld.buf + CMD_HEADER_SIZE + data_length, CMD_HEADER_SIZE + data_length);

	setup_payload(pkt, session_id, PHASE_ID_SECURE_SERVICE, CMD_HEADER_SIZE + data_length + CMD_DIGEST_SIZE);

	return 0;
}

static int validate_payload(struct pkt_t* pkt, const uint32_t session_id, const uint32_t phase_id, const uint32_t data_length) {
	uint8_t calculated_digest[PAYLOAD_DIGEST_SIZE];
	aes_cmac(payload_sc2be_key, PAYLOAD_KEY_SIZE * 8, pkt->buf, calculated_digest, PAYLOAD_HEADER_SIZE + data_length);
	if (memcmp(calculated_digest, pkt->buf + PAYLOAD_HEADER_SIZE + data_length, PAYLOAD_DIGEST_SIZE) != 0) {
		goto fail;
	}

	aes_decrypt_cbc(payload_sc2be_key, PAYLOAD_KEY_SIZE * 8, zero_iv, pkt->buf, pkt->buf, PAYLOAD_HEADER_SIZE + data_length);

	struct pld_hdr_t* header = &pkt->pld_hdr;
	if (header->packet_type != PACKET_TYPE_SC2BE) {
		goto fail;
	}

	if (header->session_id != session_id) {
		goto fail;
	}

	if (header->phase_id != phase_id) {
		goto fail;
	}

	return 0;

fail:
	return -1;
}

static int validate_encrypted_command(struct pkt_t* pkt, const uint32_t session_id, const uint32_t seq_service_id, const uint8_t session_key[SESSION_KEY_SIZE], const uint32_t data_length) {
	int result = validate_payload(pkt, session_id, PHASE_ID_SECURE_SERVICE, CMD_HEADER_SIZE + data_length + CMD_DIGEST_SIZE);
	if (result != 0) {
		goto fail;
	}

	uint8_t calculated_digest[PAYLOAD_DIGEST_SIZE];
	aes_cmac(session_key, SESSION_KEY_SIZE * 8, pkt->pld.buf, calculated_digest, CMD_HEADER_SIZE + data_length);

	aes_decrypt_cbc(session_key, SESSION_KEY_SIZE * 8, zero_iv, pkt->pld.buf, pkt->pld.buf, CMD_HEADER_SIZE + data_length);

	if (memcmp(calculated_digest, pkt->pld.buf + CMD_HEADER_SIZE + data_length, PAYLOAD_DIGEST_SIZE) != 0) {
		goto fail;
	}

	return 0;

fail:
	return -1;
}

static int create_get_system_info_cmd(struct pkt_t* pkt) {
	struct get_system_info_t* payload = &pkt->pld.get_system_info;

	memset(payload, 0, sizeof(struct get_system_info_t));

	int result = setup_payload(pkt, NO_SESSION, PHASE_ID_GET_SYSTEM_INFO, GET_SYSTEM_INFO_PAYLOAD_SIZE);
	if (result != 0) {
		goto fail;
	}

fail:
	return 0;
}

static int validate_get_system_info_cmd(struct pkt_t* pkt, const uint32_t length) {
	struct get_system_info_reply_t* payload = &pkt->pld.get_system_info_reply;

	if (length < PAYLOAD_HEADER_SIZE + PAYLOAD_DIGEST_SIZE) {
		goto fail;
	}

	int result = validate_payload(pkt, NO_SESSION, PHASE_ID_GET_SYSTEM_INFO, length - (PAYLOAD_HEADER_SIZE + PAYLOAD_DIGEST_SIZE));
	if (result != 0) {
		goto fail;
	}

	fprintf(stdout, "SYSTEM INFO:\n");
	dump_data(payload->system_info, SYSTEM_INFO_SIZE);

	return 0;

fail:
	return result;
}

static int create_auth1_cmd(struct pkt_t* pkt, const uint32_t session_id, const uint8_t host_challenge[RANDOM_CHALLENGE_SIZE]) {
	struct auth1_t* payload = &pkt->pld.auth1;

	memset(payload, 0, sizeof(struct auth1_t));
	memcpy(payload->host_challenge, host_challenge, RANDOM_CHALLENGE_SIZE);

	aes_encrypt_cbc(auth1_key, AUTH_KEY_SIZE * 8, zero_iv, payload->host_challenge, payload->host_challenge, RANDOM_CHALLENGE_SIZE);

	int result = setup_payload(pkt, session_id, PHASE_ID_AUTH1, AUTH1_PAYLOAD_SIZE);
	if (result != 0) {
		goto fail;
	}

fail:
	return 0;
}

static int validate_auth1_cmd(struct pkt_t* pkt, const uint32_t session_id, const uint8_t host_challenge[RANDOM_CHALLENGE_SIZE], uint8_t syscon_challenge[RANDOM_CHALLENGE_SIZE], const uint32_t length) {
	struct auth1_reply_t* payload = &pkt->pld.auth1_reply;

	if (length < PAYLOAD_HEADER_SIZE + PAYLOAD_DIGEST_SIZE) {
		goto fail;
	}

	int result = validate_payload(pkt, session_id, PHASE_ID_AUTH1, length - (PAYLOAD_HEADER_SIZE + PAYLOAD_DIGEST_SIZE));
	if (result != 0) {
		goto fail;
	}

	aes_decrypt_cbc(auth2_key, AUTH_KEY_SIZE * 8, zero_iv, payload->host_challenge, payload->host_challenge, RANDOM_CHALLENGE_SIZE);
	aes_decrypt_cbc(auth2_key, AUTH_KEY_SIZE * 8, zero_iv, payload->syscon_challenge, payload->syscon_challenge, RANDOM_CHALLENGE_SIZE);

	if (memcmp(payload->host_challenge, host_challenge, RANDOM_CHALLENGE_SIZE) != 0) {
		goto fail;
	}

	memcpy(syscon_challenge, payload->syscon_challenge, RANDOM_CHALLENGE_SIZE);

	return 0;

fail:
	return result;
}

static int create_auth2_cmd(struct pkt_t* pkt, const uint32_t session_id, const uint8_t syscon_challenge[RANDOM_CHALLENGE_SIZE]) {
	struct auth2_t* payload = &pkt->pld.auth2;

	memset(payload, 0, sizeof(struct auth1_t));
	memcpy(payload->syscon_challenge, syscon_challenge, RANDOM_CHALLENGE_SIZE);

	aes_encrypt_cbc(auth1_key, AUTH_KEY_SIZE * 8, zero_iv, payload->syscon_challenge, payload->syscon_challenge, RANDOM_CHALLENGE_SIZE);

	int result = setup_payload(pkt, session_id, PHASE_ID_AUTH2, AUTH2_PAYLOAD_SIZE);
	if (result != 0) {
		goto fail;
	}

fail:
	return 0;
}

static int validate_auth2_cmd(struct pkt_t* pkt, const uint32_t session_id, const uint8_t host_challenge[RANDOM_CHALLENGE_SIZE], const uint8_t syscon_challenge[RANDOM_CHALLENGE_SIZE], uint8_t session_key[SESSION_KEY_SIZE], const uint32_t length) {
	struct auth2_reply_t* payload = &pkt->pld.auth2_reply;

	if (length < PAYLOAD_HEADER_SIZE + PAYLOAD_DIGEST_SIZE) {
		goto fail;
	}

	int result = validate_payload(pkt, session_id, PHASE_ID_AUTH2, length - (PAYLOAD_HEADER_SIZE + PAYLOAD_DIGEST_SIZE));
	if (result != 0) {
		goto fail;
	}

	aes_encrypt_cbc(syscon_challenge, RANDOM_CHALLENGE_SIZE * 8, zero_iv, host_challenge, session_key, SESSION_KEY_SIZE);
	aes_encrypt_cbc(session_key_seeds[session_id], SESSION_KEY_SEED_SIZE * 8, zero_iv, session_key, session_key, SESSION_KEY_SIZE);

	aes_decrypt_cbc(session_key, SESSION_KEY_SIZE * 8, zero_iv, payload->empty_string, payload->empty_string, PAYLOAD_EMPTY_STRING_SIZE);

	if (memcmp(payload->empty_string, payload_empty_string, PAYLOAD_EMPTY_STRING_SIZE) != 0) {
		goto fail;
	}

	return 0;

fail:
	return result;
}

static int create_read_data_cmd(struct pkt_t* pkt, const uint32_t session_id, const uint32_t block_index, const uint32_t block_count, const uint32_t partition_index, const uint8_t session_key[SESSION_KEY_SIZE]) {
	struct read_data_cmd_t* cmd = &pkt->pld.cmd.read;

	memset(cmd, 0, sizeof(struct read_data_cmd_t));
	cmd->block_index = block_index;
	cmd->block_count = block_count;
	cmd->partition_index = partition_index;

	int result = setup_encrypted_command(pkt, session_id, SERVICE_ID_READ_WRITE, session_key, READ_DATA_CMD_SIZE);
	if (result != 0) {
		goto fail;
	}

fail:
	return 0;
}

static int validate_read_data_cmd(struct pkt_t* pkt, const uint32_t session_id, const uint32_t block_index, const uint32_t block_count, const uint32_t partition_index, const uint8_t session_key[SESSION_KEY_SIZE], uint8_t* const data, const uint32_t length) {
	if (length < PAYLOAD_HEADER_SIZE + CMD_HEADER_SIZE + CMD_DIGEST_SIZE + PAYLOAD_DIGEST_SIZE) {
		goto fail;
	}

	int result = validate_encrypted_command(pkt, session_id, SERVICE_ID_READ_WRITE, session_key, length - (PAYLOAD_HEADER_SIZE + CMD_HEADER_SIZE + CMD_DIGEST_SIZE + PAYLOAD_DIGEST_SIZE));
	if (result != 0) {
		goto fail;
	}

	struct read_data_cmd_reply_t* cmd = &pkt->pld.cmd.read_reply;

	if (cmd->block_index != block_index) {
		goto fail;
	}

	if (cmd->block_count != block_count) {
		goto fail;
	}

	if (cmd->partition_index != partition_index) {
		goto fail;
	}

	uint32_t data_size = cmd->block_count * BLOCK_SIZE;
	memcpy(data, cmd->data, data_size);

fail:
	return 0;
}

int main(int argc, char* argv[]) {
	int result;

	result = 0;

	struct pkt_t* pkt = (struct pkt_t*)packet_buffer;

	uint32_t session_id;
	uint32_t block_index;
	uint32_t block_count;
	uint32_t partition_index;
	uint32_t packet_size;
	uint32_t sector_start;
	uint32_t i;

	get_eid_root_key();
	
	//Checking for eid_root_key.
	if (!memcmp(eid_root_iv, zero_iv, 0x10)){
		fprintf(stderr, "ERROR: put eid_root_key file to the program directory!\n");
		return 0;
	}
	
	
#if 0
	if (argc < 5) {
		fprintf(stdout, "usage: syscon <session id> <block index> <block count> <partition index> [sector start]\n");
		return 0;
	}

	session_id = (uint32_t)atoi(argv[1]);
	block_index = (uint32_t)atoi(argv[2]);
	block_count = (uint32_t)atoi(argv[3]);
	partition_index = (uint32_t)atoi(argv[4]);

	if (argc > 5)
		sector_start = (uint32_t)atoi(argv[5]);
	else
		sector_start = -1;
#else
	session_id = 1;

//	uint8_t arg1, arg2;
//	arg1 = (uint8_t)atoi(argv[1]);
//	arg2 = (uint8_t)atoi(argv[2]);
#endif

	result = sc_startup();
	if (result != 0) {
		fprintf(stderr, "sc_startup() failed: 0x%08X\n", result);
		goto done;
	}

	generate_user_keys();
fprintf(stdout, "create_get_system_info_cmd()\n");
	
/*	uint16_t syscon_version = -1;
	
	result = sc_get_syscon_version(&syscon_version);
	if (result != 0) {
		fprintf(stdout, "sc_get_syscon_version() failed: 0x%08X\n", result);
		goto fail;
	}
	
	fprintf(stdout, "syscon version: %02X.%02X\n", (syscon_version/0x100), (syscon_version&0xFF));
*/

	uint16_t version = -1;
	
	result = sc_get_version(0x14, &version);
	if (result != 0) {
		fprintf(stdout, "sc_get_version() failed: 0x%08X\n", result);
		goto fail;
	}
	
	fprintf(stdout, "sc_version nvs: %02X.%02X\n", (version/0x100), (version&0xFF));
	
	

	if (session_id >= SESSION_COUNT) {
		fprintf(stderr, "incorrect session specified\n");
		goto fail;
	}

	result = generate_auth_keys(session_id);
	if (result != 0) {
		fprintf(stdout, "generate_auth_keys() failed: 0x%08X\n", result);
		goto fail;
	}

	uint8_t host_challenge[RANDOM_CHALLENGE_SIZE];
	result = generate_random_bytes(host_challenge, RANDOM_CHALLENGE_SIZE);
	if (result != 0) {
		fprintf(stdout, "generate_random_bytes() failed: 0x%08X\n", result);
		goto fail;
	}

#if 0
	//
	// AUTH1
	//
	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "create_auth1_cmd()\n");
	result = create_auth1_cmd(pkt, session_id, host_challenge);
	if (result != 0) {
		fprintf(stdout, "create_auth1_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	// TODO: refactor
	fprintf(stdout, "setup_packet()\n");
	result = setup_packet(&pkt->pkt_hdr, SERVICE_ID_AUTH, VERSION_0x1, 0, PAYLOAD_HEADER_SIZE + AUTH1_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "setup_packet() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet_buffer, PACKET_HEADER_SIZE + PAYLOAD_HEADER_SIZE + AUTH1_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "sc_put() failed: 0x%08X\n", result);
		goto fail;
	}

	usleep(TIMEOUT);

	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet_buffer, &packet_size);
	if (result != 0) {
		fprintf(stdout, "sc_get() failed: 0x%08X\n", result);
		goto fail;
	}

	uint32_t received_size = pkt->pkt_hdr.body_size[0];
	if (packet_size - PACKET_HEADER_SIZE != received_size) {
		goto fail;
	}

	uint8_t syscon_challenge[RANDOM_CHALLENGE_SIZE];
	fprintf(stdout, "validate_auth1_cmd()\n");
	result = validate_auth1_cmd(pkt, session_id, host_challenge, syscon_challenge, received_size);
	if (result != 0) {
		fprintf(stdout, "validate_auth1_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	//
	// AUTH2
	//
	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);
	fprintf(stdout, "create_auth2_cmd()\n");
	result = create_auth2_cmd(pkt, session_id, syscon_challenge);
	if (result != 0) {
		fprintf(stdout, "create_auth2_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	// TODO: refactor
	fprintf(stdout, "setup_packet()\n");
	result = setup_packet(&pkt->pkt_hdr, SERVICE_ID_AUTH, VERSION_0x1, 1, PAYLOAD_HEADER_SIZE + AUTH2_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "setup_packet() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet_buffer, PACKET_HEADER_SIZE + PAYLOAD_HEADER_SIZE + AUTH2_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "sc_put() failed: 0x%08X\n", result);
		goto fail;
	}

	usleep(TIMEOUT);

	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet_buffer, &packet_size);
	if (result != 0) {
		fprintf(stdout, "sc_get() failed: 0x%08X\n", result);
		goto fail;
	}

	received_size = pkt->pkt_hdr.body_size[0];
	if (packet_size - PACKET_HEADER_SIZE != received_size) {
		goto fail;
	}

	uint8_t session_key[SESSION_KEY_SIZE];
	fprintf(stdout, "validate_auth2_cmd()\n");
	result = validate_auth2_cmd(pkt, session_id, host_challenge, syscon_challenge, session_key, received_size);
	if (result != 0) {
		fprintf(stdout, "validate_auth2_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	//
	// READ DATA
	//
	// commented due to Sony's bug :(
	//memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "create_read_data_cmd()\n");
	result = create_read_data_cmd(pkt, session_id, block_index, block_count, partition_index, session_key);
	if (result != 0) {
		fprintf(stdout, "create_read_data_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	// TODO: refactor
	fprintf(stdout, "setup_packet()\n");
	result = setup_packet(&pkt->pkt_hdr, SERVICE_ID_AUTH, VERSION_0x1, 2, PAYLOAD_HEADER_SIZE + CMD_HEADER_SIZE + READ_DATA_CMD_SIZE + CMD_DIGEST_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "setup_packet() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet_buffer, PACKET_HEADER_SIZE + PAYLOAD_HEADER_SIZE + CMD_HEADER_SIZE + READ_DATA_CMD_REPLY_SIZE + CMD_DIGEST_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "sc_put() failed: 0x%08X\n", result);
		goto fail;
	}

	usleep(TIMEOUT);

	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet_buffer, &packet_size);
	if (result != 0) {
		fprintf(stdout, "sc_get() failed: 0x%08X\n", result);
		goto fail;
	}

	received_size = pkt->pkt_hdr.body_size[0];
	if (packet_size - PACKET_HEADER_SIZE != received_size) {
		goto fail;
	}

	uint8_t* data = (uint8_t*)malloc(block_count * BLOCK_SIZE);
	memset(data, 0xFF, block_count * BLOCK_SIZE);
	fprintf(stdout, "validate_read_data_cmd()\n");
	result = validate_read_data_cmd(pkt, session_id, block_index, block_count, partition_index, session_key, data, received_size);
	if (result != 0) {
		fprintf(stdout, "validate_read_data_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	//
	// DECRYPTION
	//
	if (sector_start != -1) {
		generate_xts_keys();

		fprintf(stdout, "DATA (ENC):\n");
		dump_data(data, block_count * BLOCK_SIZE);

		for (i = 0; i < block_count; ++i)
			aes_decrypt_xts(tweak_key, TWEAK_KEY_SIZE * 8, data_key, DATA_KEY_SIZE * 8, (uint8_t*)data + i * BLOCK_SIZE, (uint8_t*)data + i * BLOCK_SIZE, sector_start + i, BLOCK_SIZE);

		fprintf(stdout, "DATA (DEC):\n");
		dump_data(data, block_count * BLOCK_SIZE);
	} else {
		fprintf(stdout, "DATA:\n");
		dump_data(data, block_count * BLOCK_SIZE);
	}

	free(data);
#elif 0
	uint8_t xdr_config[XDR_CONFIG_SIZE];
	memset(xdr_config, 0, XDR_CONFIG_SIZE);
	if (sc_query_xdr_config(arg1, arg2, xdr_config) != 0) {
		fprintf(stdout, "sc_query_xdr_config() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "XDR CONFIG:\n");
	dump_data(xdr_config, XDR_CONFIG_SIZE);
#elif 0
//	uint32_t version = -1;
	uint64_t rtc = -1;

	/*if (sc_get_version(0x12, &version) != 0) {
		fprintf(stdout, "sc_get_version() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "result: 0x%08X\n", version);

	if (sc_get_rtc(&rtc) != 0) {
		fprintf(stdout, "sc_get_rtc() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "result: 0x%016llX\n", rtc);

	if (sc_get_hw_config() != 0) {
		fprintf(stdout, "sc_get_hw_config() failed: 0x%08X\n", result);
		goto fail;
	}*/

	//sc_be_shutdown();
#elif 1
	//
	// GET SYSTEM INFO
	//
	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "create_get_system_info_cmd()\n");
	result = create_get_system_info_cmd(pkt);
	if (result != 0) {
		fprintf(stdout, "create_get_system_info_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	// TODO: refactor
	fprintf(stdout, "setup_packet()\n");
	result = setup_packet(&pkt->pkt_hdr, SERVICE_ID_AUTH, VERSION_0x1, 0, PAYLOAD_HEADER_SIZE + GET_SYSTEM_INFO_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "setup_packet() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet_buffer, PACKET_HEADER_SIZE + PAYLOAD_HEADER_SIZE + GET_SYSTEM_INFO_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "sc_put() failed: 0x%08X\n", result);
		goto fail;
	}

	usleep(TIMEOUT);

	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet_buffer, &packet_size);
	if (result != 0) {
		fprintf(stdout, "sc_get() failed: 0x%08X\n", result);
		goto fail;
	}

	uint32_t received_size = pkt->pkt_hdr.body_size[0];
	if (packet_size - PACKET_HEADER_SIZE != received_size) {
		goto fail;
	}

	fprintf(stdout, "validate_get_system_info_cmd()\n");
	result = validate_get_system_info_cmd(pkt, received_size);
	if (result != 0) {
		fprintf(stdout, "validate_get_system_info_cmd() failed: 0x%08X\n", result);
		goto fail;
	}
#else
	//
	// GET STATE
	//
	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "create_get_state_cmd()\n");
	result = create_get_state_cmd(pkt);
	if (result != 0) {
		fprintf(stdout, "create_get_state_cmd() failed: 0x%08X\n", result);
		goto fail;
	}

	// TODO: refactor
	fprintf(stdout, "setup_packet()\n");
	result = setup_packet(&pkt->pkt_hdr, SERVICE_ID_AUTH, VERSION_0x1, 0, PAYLOAD_HEADER_SIZE + GET_STATE_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "setup_packet() failed: 0x%08X\n", result);
		goto fail;
	}

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet_buffer, PACKET_HEADER_SIZE + PAYLOAD_HEADER_SIZE + GET_STATE_PAYLOAD_SIZE + PAYLOAD_DIGEST_SIZE);
	if (result != 0) {
		fprintf(stdout, "sc_put() failed: 0x%08X\n", result);
		goto fail;
	}

	usleep(TIMEOUT);

	memset(packet_buffer, 0, PACKET_BUFFER_SIZE);

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet_buffer, &packet_size);
	if (result != 0) {
		fprintf(stdout, "sc_get() failed: 0x%08X\n", result);
		goto fail;
	}

	uint32_t received_size = pkt->pkt_hdr.body_size[0];
	if (packet_size - PACKET_HEADER_SIZE != received_size) {
		goto fail;
	}

	fprintf(stdout, "validate_get_state_cmd()\n");
	result = validate_get_state_cmd(pkt, received_size);
	if (result != 0) {
		fprintf(stdout, "validate_get_state_cmd() failed: 0x%08X\n", result);
		goto fail;
	}
#endif

fail:
	sc_shutdown();

done:
	return 0;
}
