/*
 * This file is part of auto_ssh_auth.
 *
 *  auto_ssh_auth is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  auto_ssh_auth is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with auto_ssh_auth.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <string.h>
#include <unistd.h>
#include <mbedtls/sha1.h>
#include <mbedtls/md.h>
#include <ctype.h>
#include "util.h"
#include "otp.h"

static void hmac(const void *key, size_t key_size, const void *msg, size_t msg_len, uint8_t *digest)
{
	const mbedtls_md_info_t *sha1;

	sha1 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
	mbedtls_md_hmac(sha1, key, key_size, msg, msg_len, digest);
}

void otp_totp(const void *secret, size_t secret_size, char digest[6])
{
	time_t tick;
	uint32_t tick_normal;
	uint8_t message[8] = {0};
	uint8_t sha_digest[20];
	int offset;
	uint32_t number;

	tick = time(NULL) / 30;
	if (tick > UINT32_MAX) {
		fprintf(stderr, "Future!\n");
		abort();
	}

	tick_normal = htobe32((uint32_t) tick);
	memcpy(message + 4, &tick_normal, 4);
	hmac(secret, secret_size, message, sizeof(message), sha_digest);

	offset = sha_digest[sizeof(sha_digest) - 1] & 0xf;
	number = (be32toh(*(uint32_t *) (sha_digest + offset)) & 0x7fffffff);

	digest[5] = (char) ('0' + number % 10);
	number /= 10;
	digest[4] = (char) ('0' + number % 10);
	number /= 10;
	digest[3] = (char) ('0' + number % 10);
	number /= 10;
	digest[2] = (char) ('0' + number % 10);
	number /= 10;
	digest[1] = (char) ('0' + number % 10);
	number /= 10;
	digest[0] = (char) ('0' + number % 10);
}