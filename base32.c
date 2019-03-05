#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include "util.h"

static const uint8_t b32[0x100] = {
	['A']= 0,
	['B']= 1,
	['C']= 2,
	['D']= 3,
	['E']= 4,
	['F']= 5,
	['G']= 6,
	['H']= 7,
	['I']= 8,
	['J']= 9,
	['K']= 10,
	['L']= 11,
	['M']= 12,
	['N']= 13,
	['O']= 14,
	['P']= 15,
	['Q']= 16,
	['R']= 17,
	['S']= 18,
	['T']= 19,
	['U']= 20,
	['V']= 21,
	['W']= 22,
	['X']= 23,
	['Y']= 24,
	['Z']= 25,
	['2']= 26,
	['3']= 27,
	['4']= 28,
	['5']= 29,
	['6']= 30,
	['7']= 31,
};

static int decode_8(char const *restrict in, uint8_t *restrict outp)
{
	uint8_t *out = outp;

	*out++ = ((b32[in[0]] << 3)
	          | (b32[in[1]] >> 2));

	if (in[2] == '=') {
		if (in[3] != '=' || in[4] != '=' || in[5] != '='
		    || in[6] != '=' || in[7] != '=')
			return -1;
	} else {
		*out++ = ((b32[in[1]] << 6)
		          | (b32[in[2]] << 1)
		          | (b32[in[3]] >> 4));

		if (in[4] == '=') {
			if (in[5] != '=' || in[6] != '=' || in[7] != '=')
				return -1;
		} else {
			*out++ = ((b32[in[3]] << 4)
			          | (b32[in[4]] >> 1));

			if (in[5] == '=') {
				if (in[6] != '=' || in[7] != '=')
					return -1;
			} else {
				*out++ = ((b32[in[4]] << 7)
				          | (b32[in[5]] << 2)
				          | (b32[in[6]] >> 3));

				if (in[7] != '=') {
					*out++ = ((b32[in[6]] << 5)
					          | (b32[in[7]]));
				}
			}
		}
	}

	return (int) (out - outp);
}

int base32_decode(const char *input, uint8_t *out)
{
	const char *p = input;
	int n, rc = 0;
	while (*p) {
		if (p[0] == 0 || p[1] == 0 || p[2] == 0 || p[3] == 0 ||
		    p[4] == 0 || p[5] == 0 || p[6] == 0 || p[7] == 0
			) {
			break;
		}
		n = decode_8(p, out);
		if (n < 0) {
			break;
		}
		p += 8;
		out += n;
		rc += n;
	}
	return rc;
}