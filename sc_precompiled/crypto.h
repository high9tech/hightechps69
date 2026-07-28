/**
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "common.h"

//-----------------------------------------------------------------------------
// AES
//-----------------------------------------------------------------------------

enum {
	AES_DECRYPT = 0,
	AES_ENCRYPT = 1,

	AES_BLOCK_SIZE = 16,
};

enum {
	// Invalid mode
	ERROR_INVALID_MODE = -1,

	// Invalid key length
	ERROR_INVALID_KEY_SIZE = -2,

	// Invalid data size
	ERROR_INVALID_DATA_SIZE = -3,
};

// 
// \brief AES context structure
// 
// \note  buf is able to hold 32 extra bytes, which can be used:
//        to simplify key expansion in the 256-bit case by generating an extra round key
// 
struct aes_context_t {
	uint32_t buf[68]; // unaligned data
	uint32_t* rk; // round keys
	int nr; // number of rounds
	int mode; // AES_ENCRYPT or AES_DECRYPT
};

// 
// \brief AES-XTS context structure
// 
struct aes_xts_context_t {
	struct aes_context_t tweak_ctx;
	struct aes_context_t data_ctx;
	int mode;
};

// 
// \brief          AES key schedule
// 
// \param ctx      AES context to be initialized
// \param mode     AES_ENCRYPT or AES_DECRYPT
// \param key      decryption key
// \param key_size must be 128, 192 or 256
// 
// \return         0 if successful, or ERROR_INVALID_KEY_SIZE
// 
int aes_init(struct aes_context_t* const ctx, const int mode, const uint8_t* const key, const unsigned int key_size);

// 
// \brief        AES-ECB block encryption/decryption
// 
// \param ctx    AES context
// \param input  16-byte input block
// \param output 16-byte output block
// 
// \return       0 if successful
// 
int aes_crypt_ecb(struct aes_context_t* const ctx, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE]);
int aes_encrypt_ecb(const uint8_t* const key, const int key_size, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE], const uint32_t length);
int aes_decrypt_ecb(const uint8_t* const key, const int key_size, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE], const uint32_t length);

// 
// \brief        AES-CBC buffer encryption/decryption
//               Length should be a multiple of the block size (16 bytes)
// 
// \param ctx    AES context
// \param mode   AES_ENCRYPT or AES_DECRYPT
// \param length length of the input data
// \param iv     initialization vector (updated after use)
// \param input  buffer holding the input data
// \param output buffer holding the output data
// 
// \return       0 if successful, or ERROR_INVALID_DATA_SIZE
// 
int aes_crypt_cbc(struct aes_context_t* const ctx, uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);
int aes_encrypt_cbc(const uint8_t* const key, const int key_size, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);
int aes_decrypt_cbc(const uint8_t* const key, const int key_size, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);

// 
// \brief         AES-CTR buffer encryption/decryption
// 
// \param ctx     AES context
// \param nonce   The 128-bit nonce
// \param length  The length of the data
// \param input   buffer holding the input data
// \param output  buffer holding the output data
// 
// \return        0 if successful
// 
int aes_crypt_ctr(struct aes_context_t* const ctx, uint8_t nonce[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);
int aes_ctr(const uint8_t* const key, const int key_size, const uint8_t nonce[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);

// 
// \brief AES-XTS key schedule
// 
int aes_xts_init(struct aes_xts_context_t* const ctx, const int mode, const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size);

// 
// \brief AES-XTS sector encryption/decryption
// 
int aes_crypt_xts(struct aes_xts_context_t* const ctx, const uint8_t* const input, uint8_t* const output, const uint64_t sector_index, const uint32_t sector_size);
int aes_encrypt_xts(const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size, const uint8_t* const input, uint8_t* const output, const uint32_t sector_index, const uint32_t sector_size);
int aes_decrypt_xts(const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size, const uint8_t* const input, uint8_t* const output, const uint32_t sector_index, const uint32_t sector_size);

// 
// \brief AES-CMAC
// 
int aes_cmac(const uint8_t* const key, const int key_size, const uint8_t* const input, uint8_t* const output, const uint32_t length);

//-----------------------------------------------------------------------------
// SHA-1
//-----------------------------------------------------------------------------

enum {
	SHA1_HASH_SIZE = 20,
	SHA1_BLOCK_SIZE = 64,
};

//
// \brief SHA-1 context structure
//
struct sha1_context_t {
	uint32_t total[2]; // number of bytes processed
	uint32_t state[5]; // intermediate digest state
	uint8_t buffer[64]; // data block being processed
	uint8_t ipad[64]; // HMAC: inner padding
	uint8_t opad[64]; // HMAC: outer padding
};

// 
// \brief     SHA-1 context setup
// 
// \param ctx context to be initialized
// 
void sha1_starts(struct sha1_context_t* const ctx);

// For internal use
void sha1_transform(struct sha1_context_t* const ctx, const uint8_t data[SHA1_BLOCK_SIZE]);

// 
// \brief        SHA-1 process buffer
// 
// \param ctx    SHA-1 context
// \param input  buffer holding the data
// \param length length of the input data
// 
void sha1_update(struct sha1_context_t* const ctx, const uint8_t* const input, const uint32_t length);

// 
// \brief        SHA-1 final digest
// 
// \param ctx    SHA-1 context
// \param output SHA-1 checksum result
// 
void sha1_finish(struct sha1_context_t* const ctx, uint8_t output[SHA1_HASH_SIZE]);

// 
// \brief        Output = SHA-1(input buffer)
// 
// \param input  buffer holding the data
// \param output SHA-1 checksum result
// \param length length of the input data
// 
void sha1(const uint8_t* const input, uint8_t output[SHA1_HASH_SIZE], const uint32_t length);

// 
// \brief          SHA-1 HMAC context setup
// 
// \param ctx      HMAC context to be initialized
// \param key      HMAC secret key
// \param key_size length of the HMAC key
// 
void sha1_hmac_starts(struct sha1_context_t* const ctx, const uint8_t* const key, const uint32_t key_size);

// 
// \brief        SHA-1 HMAC process buffer
// 
// \param ctx    HMAC context
// \param input  buffer holding the  data
// \param length length of the input data
// 
void sha1_hmac_update(struct sha1_context_t* const ctx, const uint8_t* const input, const uint32_t length);

// 
// \brief        SHA-1 HMAC final digest
// 
// \param ctx    HMAC context
// \param output SHA-1 HMAC checksum result
// 
void sha1_hmac_finish(struct sha1_context_t* const ctx, uint8_t output[SHA1_HASH_SIZE]);

// 
// \brief     SHA-1 HMAC context reset
// 
// \param ctx HMAC context to be reset
// 
void sha1_hmac_reset(struct sha1_context_t* const ctx);

// 
// \brief          Output = HMAC-SHA-1(hmac key, input buffer)
// 
// \param key      HMAC secret key
// \param key_size length of the HMAC key
// \param input    buffer holding the  data
// \param output   HMAC-SHA-1 result
// \param length   length of the input data
// 
void sha1_hmac(const uint8_t* const key, const uint32_t key_size, const uint8_t* const input, uint8_t output[SHA1_HASH_SIZE], const uint32_t length);

//-----------------------------------------------------------------------------
// Random numbers generation
//-----------------------------------------------------------------------------

int generate_random_bytes(uint8_t* const data, const uint32_t length);

#endif
