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

#ifndef AUTO_SSH_AUTH_UTIL_H
#define AUTO_SSH_AUTH_UTIL_H

#include <stdlib.h>
#include <stdio.h>

#define FATAL(fmt, ...) do {\
  fprintf(stderr, "%s:%d: "fmt"(errno=%d)\n", __FILE__, __LINE__,##__VA_ARGS__, errno);\
  _exit(1); \
}while(0)
#define min(a, b) ((a)<(b)?(a):(b))
#endif //AUTO_SSH_AUTH_UTIL_H
