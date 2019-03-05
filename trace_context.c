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
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include "util.h"
#include "trace_context.h"
#include "strsyscall.h"

# ifndef PTRACE_GET_SYSCALL_INFO
#  define PTRACE_GET_SYSCALL_INFO    0x420e
#  define PTRACE_SYSCALL_INFO_NONE    0
#  define PTRACE_SYSCALL_INFO_ENTRY    1
#  define PTRACE_SYSCALL_INFO_EXIT    2
#  define PTRACE_SYSCALL_INFO_SECCOMP    3
struct ptrace_syscall_info {
	uint8_t op;
	uint8_t pad[3];
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t stack_pointer;
	union {
		struct {
			uint64_t nr;
			uint64_t args[6];
		} entry;
		struct {
			int64_t rval;
			uint8_t is_error;
		} exit;
		struct {
			uint64_t nr;
			uint64_t args[6];
			uint32_t ret_data;
		} seccomp;
	};
};
# endif

ssize_t trace_pread(struct trace_context *tc, void *buf, size_t count, uintptr_t addr)
{
	return pread(tc->memfd, buf, count, addr);
}

ssize_t trace_pwrite(struct trace_context *tc, const void *buf, size_t count, uintptr_t addr)
{
	return pwrite(tc->memfd, buf, count, addr);
}

ssize_t trace_copy_cstr(struct trace_context *tc, char *buf, size_t count, uintptr_t addr)
{
	size_t copy_size;
	ssize_t n;
	size_t remains = count;
	char *p = buf;
	uintptr_t next = addr;

	copy_size = min(((addr + (PAGE_SIZE - 1)) & PAGE_MASK) - addr, count);
	while (remains > 0) {
		n = pread(tc->memfd, p, copy_size, next);
		if (n < 0) {
			fprintf(stderr, "pread: %s\n", strerror(errno));
			return -1;
		}
		if (n < copy_size || strnlen(p, copy_size) < copy_size) {
			goto out;
		}
		p += n;
		next += n;
		remains -= n;
		copy_size = min(PAGE_SIZE, remains);
	}

out:
	return p - buf;
}

int trace_step(struct trace_context *tc)
{
	long rc;
	int status;
	struct ptrace_syscall_info info = {
		.op = 0xff    /* invalid PTRACE_SYSCALL_INFO_* op */
	};
	int sig = 0;

	while (1) {
		rc = ptrace(PTRACE_SYSCALL, tc->pid, 0, sig);
		if (rc < 0) {
			FATAL("ptrace: %s\n", strerror(errno));
		}
		rc = waitpid(tc->pid, &status, 0);
		if (rc != tc->pid) {
			FATAL("waitpid: %s\n", strerror(errno));
		}
		if (WIFEXITED(status)) {
			FATAL("process exited with code %d???\n", WEXITSTATUS(status));
		}
		if (WIFSIGNALED(status)) {
			FATAL("process exited with signal %d???\n", WTERMSIG(status));
		}
		if (!WIFSTOPPED(status)) {
			FATAL("Unexpected stop status: %x\n", status);
		}
		sig = WSTOPSIG(status);
		switch (sig) {
		case SIGSTOP:
			if (ptrace(PTRACE_SETOPTIONS, tc->pid, 0L, PTRACE_O_TRACESYSGOOD) < 0) {
				FATAL("PTRACE_O_TRACESYSGOOD: %s\n", strerror(errno));
			}
			rc = ptrace(PTRACE_GET_SYSCALL_INFO, tc->pid, (void *) sizeof(info), &info);
			if (rc < 0) {
				FATAL("PTRACE_GET_SYSCALL_INFO: %s\n", strerror(errno));
			}
			break;
		case SIGTRAP | 0x80:
			rc = ptrace(PTRACE_GETREGS, tc->pid, 0, &tc->regs);
			if (rc < 0) {
				FATAL("PTRACE_GETREGS: %s\n", strerror(errno));
			}
			return 0;
		default:
			fprintf(stderr, "received signal %s\n", strsignal(sig));
			continue;
		}
	}
	abort();
}


void trace_commit_regs(struct trace_context *tc)
{
	long rc;
	rc = ptrace(PTRACE_SETREGS, tc->pid, 0, &tc->regs);
	if (rc < 0) {
		FATAL("PTRACE_SETREGS: %s\n", strerror(errno));
	}
}

void trace_block(struct trace_context *tc)
{
	tc->regs.orig_rax = (unsigned long long int) -1;
	trace_commit_regs(tc);
	trace_step(tc);
}

int trace_exec(struct trace_context *tc, char **argv)
{
	pid_t pid;
	int memfd;
	int state;
	char mem_file[100];

	pid = fork();
	switch (pid) {
	case -1:
		FATAL("fork: %s\n", strerror(errno));
	case 0:
		ptrace(PTRACE_TRACEME);
		// raise(SIGSTOP);  SIGSTOP makes problems.. we do not love it
		execvp(argv[0], argv);
	default:
		pid = waitpid(pid, &state, WSTOPPED);
		if (pid < 0) {
			FATAL("waitpid: %s\n", strerror(errno));
		}
		ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL |
		                                  PTRACE_O_TRACESYSGOOD |
		                                  PTRACE_O_TRACEEXEC);
		sprintf(mem_file, "/proc/%d/mem", pid);
		memfd = open(mem_file, O_RDWR);
		if (memfd < 0) {
			FATAL("open %s: %s\n", mem_file, strerror(errno));
		}
	}

	tc->pid = pid;
	tc->memfd = memfd;
	FD_ZERO(&tc->tty_fd);
	FD_SET(STDIN_FILENO, &tc->tty_fd);
	FD_SET(STDOUT_FILENO, &tc->tty_fd);
	FD_SET(STDERR_FILENO, &tc->tty_fd);
	tc->drain_data = 0;

	return 0;
}


static int sys_openat_entry(struct trace_context *tc, const char *filename, int flags)
{
	struct user_regs_struct *regs = &tc->regs;
	int sfd;

	if ((flags & O_ACCMODE) == O_WRONLY || flags & O_CREAT || strcmp(filename, "/dev/tty") != 0) {
		return SYSCALL_BYPASS;
	}

	trace_step(tc);
	sfd = (int) regs->rax;
	if (sfd >= 0) {
		printf("new fd %d\n", sfd);
		FD_SET(sfd, &tc->tty_fd);
	}
	return SYSCALL_HANDLED;
}

static int hook_open(struct trace_context *tc)
{
	struct user_regs_struct *regs = &tc->regs;
	uintptr_t spathname = regs->rdi;
	int sflags = (int) regs->rsi;
	char pathname[FILENAME_MAX];
	ssize_t n;

	n = trace_copy_cstr(tc, pathname, sizeof(pathname), spathname);
	if (n < 0) {
		return SYSCALL_BYPASS;
	}

	return sys_openat_entry(tc, pathname, sflags);
}

static int hook_openat(struct trace_context *tc)
{
	struct user_regs_struct *regs = &tc->regs;
	int dirfd = (int) regs->rdi;
	uintptr_t spathname = regs->rsi;
	int sflags = (int) regs->rdx;
	char pathname[FILENAME_MAX];
	ssize_t n;

	n = trace_copy_cstr(tc, pathname, sizeof(pathname), spathname);
	if (n < 0) {
		return SYSCALL_BYPASS;
	}
	if (dirfd != AT_FDCWD) {
		return SYSCALL_BYPASS;
	}
	return sys_openat_entry(tc, pathname, sflags);
}

static int hook_dup(struct trace_context *tc)
{
	struct user_regs_struct *regs = &tc->regs;
	int oldfd = (int) regs->rdi,
		newfd;

	if (!FD_ISSET(oldfd, &tc->tty_fd)) {
		return SYSCALL_BYPASS;
	}
	trace_step(tc);
	newfd = (int) regs->rax;
	if (newfd >= 0) {
		printf("dup fd %d -> %d\n", oldfd, newfd);
		FD_SET(newfd, &tc->tty_fd);
	}
	return SYSCALL_HANDLED;
}

static int hook_close(struct trace_context *tc)
{
	struct user_regs_struct *regs = &tc->regs;
	int fd = (int) regs->rdi;
	if (FD_ISSET(fd, &tc->tty_fd)) {
		FD_CLR(fd, &tc->tty_fd);
	}
	return SYSCALL_BYPASS;
}

static int hook_write(struct trace_context *tc)
{
	struct user_regs_struct *regs = &tc->regs;
	int sfd = (int) regs->rdi;
	uintptr_t sbuf = regs->rsi;
	size_t count = regs->rdx;

	if (!FD_ISSET(sfd, &tc->tty_fd)) {
		return SYSCALL_BYPASS;
	}

	printf("tty write fd %d\n", sfd);
	return tc->tty_write(tc, sbuf, count);
}

static int hook_select(struct trace_context *tc)
{
	struct user_regs_struct *regs = &tc->regs;
	int snfds = (int) regs->rdi;
	uintptr_t sreadfds = regs->rsi,
		swritefds = regs->rdx,
		sexceptfds = regs->r10,
		stimeout = regs->r8;
	ssize_t n;
	fd_set readfds = {0}, fdset = {0};
	int active_fd;
	size_t byte_in_use = (size_t) (snfds / 8);

	if (!tc->drain_data) {
		return SYSCALL_BYPASS;
	}

	n = trace_pread(tc, &readfds, byte_in_use, sreadfds);
	n = trace_pread(tc, &fdset, byte_in_use, swritefds);
	for (int i = 0; i < min(snfds, FD_SETSIZE); ++i) {
		if (FD_ISSET(i, &tc->tty_fd) && FD_ISSET(i, &readfds)) {
			active_fd = i;
			goto found;
		}
	}
	return SYSCALL_BYPASS;
found:
	trace_block(tc);

	regs->rax = 1;
	FD_ZERO(&readfds);
	FD_SET(active_fd, &readfds);

	FD_ZERO(&fdset);
	n = trace_pwrite(tc, &readfds, byte_in_use, sreadfds);
	if (n < 0) {
		FATAL("trace_pwrite: %s\n", strerror(errno));
	}
	if (swritefds) {
		n = trace_pwrite(tc, &fdset, byte_in_use, swritefds);
		if (n < 0) {
			FATAL("trace_pwrite: %s\n", strerror(errno));
		}
	}
	if (sexceptfds) {
		n = trace_pwrite(tc, &fdset, byte_in_use, sexceptfds);
		if (n < 0) {
			FATAL("trace_pwrite: %s\n", strerror(errno));
		}
	}
	trace_commit_regs(tc);
	return SYSCALL_HANDLED;
}

int trace_next(struct trace_context *tc)
{
	int rc;
	int op;

	rc = trace_step(tc);
	if (rc < 0) {
		return rc;
	}

	printf("SYSCALL: %s\n", strsyscall((int) tc->regs.orig_rax));
	switch (tc->regs.orig_rax) {
	case __NR_open:
		op = hook_open(tc);
		break;
	case __NR_openat:
		op = hook_openat(tc);
		break;
	case __NR_dup:
		op = hook_dup(tc);
		break;
	case __NR_close:
		op = hook_close(tc);
		break;
	case __NR_write:
		op = hook_write(tc);
		break;
	case __NR_select:
		op = hook_select(tc);
		break;
	default:
		op = SYSCALL_BYPASS;
		break;
	}

	if (op != SYSCALL_HANDLED) {
		trace_step(tc);
	}

	return 0;
}
