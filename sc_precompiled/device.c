#include "device.h"

#define SYSCON_PKT_SEND_AREA    0x8C000
#define SYSCON_PKT_RECV_AREA    0x8D000
#define SYSCON_PKT_SEND_CTR     0x8CFF0
#define SYSCON_PKT_RECV_CTR     0x8DFF0
#define SYSCON_PKT_SEND_ACK_CTR 0x8CFF4
#define SYSCON_PKT_RECV_ACK_CTR 0x8DFF4
#define SYSCON_PKT_KICK         0x8E100
#define SYSCON_PKT_BUFFER_SIZE  0xFF0

static int device = -1;

int sc_startup(void) {
	if (device < 0) {
		device = open("/dev/ps3sbmmio", O_RDWR);
		if (device < 0) {
			fprintf(stderr, "unable to open /dev/ps3sbmmio\n"); 
			return -1;
		}
	}

	return 0;
}

void sc_shutdown(void) {
	if (device < 0)
		return;

	close(device);
	device = -1;
}

int sc_get(void* const data, uint32_t* const data_size) {
	uint32_t size;

	struct pkt_hdr_t* hdr = (struct pkt_hdr_t*)data;

	// Read packet header
	lseek(device, SYSCON_PKT_SEND_AREA, SEEK_SET);
	read(device, data, PACKET_HEADER_SIZE);

	size = PACKET_HEADER_SIZE + hdr->body_size[0];

	// Read packet payload
	lseek(device, SYSCON_PKT_SEND_AREA, SEEK_SET);
	read(device, data, size);

	if (data_size)
		*data_size = size;

	dump_data(data, size);

	return 0;
}

int sc_put(const void* const data, const uint32_t buffer_size) {
	uint8_t buffer[SYSCON_PKT_BUFFER_SIZE];

	uint32_t be_send_ctr, sc_send_ctr;
	uint32_t cksum, size, pad_size;
	uint32_t one;

	struct pkt_hdr_t* hdr = (struct pkt_hdr_t*)data;

	size = PACKET_HEADER_SIZE + hdr->body_size[0];
	if (size > buffer_size)
		return -1;
	pad_size = align_up(hdr->body_size[0], 4) - hdr->body_size[0];

	// Generate checksum
	cksum = sc_calc_pkt_cksum(data, size);

	memset(buffer, 0, SYSCON_PKT_BUFFER_SIZE);
	memcpy(buffer, data, size);
	memcpy(buffer + size + pad_size, &cksum, sizeof(cksum));
	dump_data(buffer, size + pad_size + sizeof(cksum));

	// Get actual packet counter
	lseek(device, SYSCON_PKT_RECV_CTR, SEEK_SET);
	read(device, &be_send_ctr, sizeof(be_send_ctr));

	// Update packet counter
	be_send_ctr = (((be_send_ctr >> 16) + 1) << 16) + ((be_send_ctr >> 16) + 1);
	lseek(device, SYSCON_PKT_RECV_CTR, SEEK_SET);
	write(device, &be_send_ctr, sizeof(be_send_ctr));

	// Write packet
	lseek(device, SYSCON_PKT_RECV_AREA, SEEK_SET);
	write(device, buffer, size + pad_size + sizeof(cksum));

	// Kick packet
	one = 1;
	lseek(device, SYSCON_PKT_KICK, SEEK_SET);
	write(device, &one, sizeof(one));

	do {
		lseek(device, SYSCON_PKT_SEND_ACK_CTR, SEEK_SET);
		read(device, &sc_send_ctr, sizeof(sc_send_ctr));
	} while (sc_send_ctr != be_send_ctr);

	usleep(TIMEOUT);

	return 0;
}

uint16_t sc_calc_hdr_cksum(void* const data) {
	uint8_t* ptr;
	uint32_t cksum;
	uint32_t i;

	ptr = (uint8_t*)data;

	cksum = 0;
	for (i = 0; i < 6; ++i)
		cksum += ptr[i];
	cksum += 0x8000;
	cksum &= 0xFFFF;

	return cksum;
}

uint16_t sc_calc_pkt_cksum(const void* const data, const uint32_t size) {
	const uint8_t* ptr;
	uint32_t cksum;
	uint32_t i;

	ptr = (const uint8_t*)data;

	cksum = 0;
	for (i = 0; i < size; ++i)
		cksum -= ptr[i];
	cksum &= 0xFFFF;

	return cksum;
}

int sc_get_hw_config(void) {
	int result;

	uint8_t packet[0x100];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_get_hw_config_request_t* pld;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_CONFIG;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 0;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_get_hw_config_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	pld = (struct pkt_get_hw_config_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(pld, 0, sizeof(struct pkt_get_hw_config_request_t));
	pld->unk1 = 0x22;

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_get_hw_config_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet, &size);
	if (result != 0) {
		fprintf(stderr, "sc_get() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	return 0;

fail:
	return result;
}

int sc_get_version(uint8_t arg, uint16_t* version) {
	int result;

	uint8_t packet[0x100];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_get_version_request_t* req;
	struct pkt_get_version_response_t* resp;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_VERSION;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 0;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_get_version_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	req = (struct pkt_get_version_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(req, 0, sizeof(struct pkt_get_version_request_t));
	req->cmd = 0x01;
	req->service_id = arg;

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_get_version_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet, &size);
	if (result != 0) {
		fprintf(stderr, "sc_get() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}
	
	resp = (struct pkt_get_version_response_t*)(packet + PACKET_HEADER_SIZE);
	if (version)
		*version = (resp->version);
	
	
	return 0;

fail:
	return result;
}

/*int sc_get_syscon_version(uint16_t* version) {
	int result;

	uint8_t packet[0x100];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_get_syscon_version_request_t* req;
	struct pkt_get_syscon_version_response_t* resp;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_VERSION;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 0;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_get_syscon_version_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	req = (struct pkt_get_syscon_version_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(req, 0, sizeof(struct pkt_get_syscon_version_request_t));
	req->cmd = 0x12;

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_get_syscon_version_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet, &size);
	if (result != 0) {
		fprintf(stderr, "sc_get() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}
	
	resp = (struct pkt_get_syscon_version_response_t*)(packet + PACKET_HEADER_SIZE);
	if (version)
		*version = (resp->version);
	
	
	return 0;

fail:
	return result;
}*/

int sc_get_rtc(uint64_t* rtc) {
	int result;

	uint8_t packet[0x100];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_get_rtc_request_t* req;
	struct pkt_get_rtc_response_t* resp;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_POWER;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 4;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_get_rtc_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	req = (struct pkt_get_rtc_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(req, 0, sizeof(struct pkt_get_rtc_request_t));
	req->unk1 = 0x33;

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_get_rtc_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet, &size);
	if (result != 0) {
		fprintf(stderr, "sc_get() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	resp = (struct pkt_get_rtc_response_t*)(packet + PACKET_HEADER_SIZE);
	if (rtc)
		*rtc = resp->rtc;

	return 0;

fail:
	return result;
}

int sc_query_xdr_config(uint8_t arg1, uint8_t arg2, uint8_t data[XDR_CONFIG_SIZE]) {
	int result;

	uint8_t packet[0x200];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_query_xdr_config_request_t* req;
	struct pkt_query_xdr_config_response_t* resp;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_CONFIG;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 1;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_query_xdr_config_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	req = (struct pkt_query_xdr_config_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(req, 0, sizeof(struct pkt_query_xdr_config_request_t));
	req->unk1 = arg1;
	req->unk2 = arg2;

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_query_xdr_config_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet, &size);
	if (result != 0) {
		fprintf(stderr, "sc_get() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	resp = (struct pkt_query_xdr_config_response_t*)(packet + PACKET_HEADER_SIZE);
	if (data)
		memcpy(data, resp->data, XDR_CONFIG_SIZE);

	return 0;

fail:
	return result;
}

int sc_beep(int type) {
	int result;

	uint8_t packet[0x100];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_ring_buzzer_request_t* pld;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_LED_BUZZER;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 1;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_ring_buzzer_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	pld = (struct pkt_ring_buzzer_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(pld, 0, sizeof(struct pkt_ring_buzzer_request_t));
	pld->res1 = 0x20;

	switch (type) {
		case BEEP_SINGLE:
			pld->field1 = 0x29;
			pld->field2 = 0x4;
			pld->field4 = 0x6;
			break;

		case BEEP_DOUBLE:
			pld->field1 = 0x29;
			pld->field2 = 0xA;
			pld->field4 = 0x1B6;
			break;

		case BEEP_CONTINUOUS:
			pld->field1 = 0x29;
			pld->field2 = 0xA;
			pld->field4 = 0xFFF;
			break;
	}

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_ring_buzzer_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet, &size);
	if (result != 0) {
		fprintf(stderr, "sc_get() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	return 0;

fail:
	return result;
}

int sc_be_shutdown(void) {
	int result;

	uint8_t packet[0x100];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_shutdown_request_t* req;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_POWER;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 0;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_shutdown_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	req = (struct pkt_shutdown_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(req, 0, sizeof(struct pkt_shutdown_request_t));
	req->unk1 = 0;

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_shutdown_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	return 0;

fail:
	return result;
}

int sc_nvs_read(uint32_t block, uint32_t offset, uint32_t length) {
	int result;

	uint8_t packet[0x100];
	uint32_t size;

	struct pkt_hdr_t* hdr;
	struct pkt_nvs_request_t* pld;

	memset(packet, 0, sizeof(packet));

	hdr = (struct pkt_hdr_t*)packet;
	memset(hdr, 0, sizeof(struct pkt_hdr_t));
	hdr->service_id = SERVICE_ID_NVS;
	hdr->version = VERSION_0x1;
	hdr->communication_tag = 0;
	hdr->body_size[0] = hdr->body_size[1] = sizeof(struct pkt_nvs_request_t);
	hdr->checksum = sc_calc_hdr_cksum(hdr);

	pld = (struct pkt_nvs_request_t*)(packet + PACKET_HEADER_SIZE);
	memset(pld, 0, sizeof(struct pkt_nvs_request_t));
	pld->cmd = NVS_READ;
	pld->block = block;
	pld->offset = offset;
	pld->length = length;

	size = PACKET_HEADER_SIZE + sizeof(struct pkt_nvs_request_t);

	fprintf(stdout, "sc_put()\n");
	result = sc_put(packet, size);
	if (result != 0) {
		fprintf(stderr, "sc_put() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	fprintf(stdout, "sc_get()\n");
	result = sc_get(packet, &size);
	if (result != 0) {
		fprintf(stderr, "sc_get() failed: 0x%08X\n", result);
		result = -EFAULT;
		goto fail;
	}

	return 0;

fail:
	return result;
}
