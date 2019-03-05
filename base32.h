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

#ifndef AUTO_SSH_AUTH_BASE32_H
#define AUTO_SSH_AUTH_BASE32_H

#include <stdint.h>
int base32_decode(const char *input, uint8_t *out);

#endif //AUTO_SSH_AUTH_BASE32_H
