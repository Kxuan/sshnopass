/*
 * This file is part of sshnopass.
 *
 *  sshnopass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  sshnopass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with sshnopass.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef AUTO_SSH_AUTH_TRACER_H
#define AUTO_SSH_AUTH_TRACER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <syscall.h>
#include <limits.h>

#define SYSCALL_BYPASS INT_MIN
#define SYSCALL_HANDLED (INT_MIN+1)

struct trace_context {
	pid_t pid;
	int memfd;

	fd_set tty_fd;

	struct user_regs_struct regs;
	int drain_data;

	int (*tty_read)(struct trace_context *tc, uintptr_t buf, size_t count);

	int (*tty_write)(struct trace_context *tc, uintptr_t buf, size_t count);

/*	int (*sys_select)(struct trace_context *tc,
	                  int nfds, uintptr_t readfds, uintptr_t writefds,
	                  uintptr_t exceptfds, uintptr_t timeout
	);*/
};

int trace_exec(struct trace_context *tc, char **argv);

ssize_t trace_pwrite(struct trace_context *tc, const void *buf, size_t count, uintptr_t addr);

ssize_t trace_pread(struct trace_context *tc, void *buf, size_t count, uintptr_t addr);

ssize_t trace_copy_cstr(struct trace_context *tc, char *buf, size_t count, uintptr_t addr);

void trace_commit_regs(struct trace_context *tc);

void trace_block(struct trace_context *tc);

int trace_step(struct trace_context *tc);

int trace_next(struct trace_context *tc);

void trace_detach(struct trace_context *tc);

#endif //AUTO_SSH_AUTH_TRACER_H
