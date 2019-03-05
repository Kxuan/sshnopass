#include <unistd.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <wait.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/user.h>
#include <syscall.h>
#include <stdint-gcc.h>
#include <fcntl.h>
#include <malloc.h>
#include <event.h>
#include "trace_context.h"

static const char *prog_name = "hack_ssh_auth";
static pid_t ssh_pid = -1;
static int ssh_mem_fd = -1;

#define PROMPT_PASSWORD "\nYour [EMAIL] password: "
#define PROMPT_TOKEN "\nYour [VPN] token: "
#define SSH_INPUT_FD 6
#define SSH_OUTPUT_FD 7

static enum {
	STATE_PROMPT_PASSWORD,
	STATE_FEED_PASSWORD,
	STATE_PROMPT_TOKEN,
	STATE_FEED_TOKEN,
	STATE_DONE
} state;

int msg(const char *fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog_name);
	rc = vfprintf(stderr, fmt, ap);
	va_end(ap);
	return rc;
}

#define FATAL(...) do {msg(__VA_ARGS__); _exit(1);} while(0)
#define min(a, b) ((a)<(b)?(a):(b))

ssize_t download_memory(void *dst, size_t nbytes, uintptr_t src)
{
	ssize_t n;

	n = pread(ssh_mem_fd, dst, nbytes, src);
	if (n != nbytes) {
		FATAL("Unable to download memory: %s\n", strerror(errno));
	}
	return n;
}

ssize_t upload_memory(const void *src, size_t nbytes, uintptr_t dst)
{
	ssize_t n;

	n = pwrite(ssh_mem_fd, src, nbytes, dst);
	if (n != nbytes) {
		FATAL("Unable to upload memory: %s\n", strerror(errno));
	}
	return n;
}

static int match_prompt(struct trace_context *tc, const char *prompt, size_t size)
{
	switch (state) {
	case STATE_PROMPT_PASSWORD:
		if (memcmp(prompt + size - sizeof(PROMPT_PASSWORD), PROMPT_PASSWORD, sizeof(PROMPT_PASSWORD) - 1) == 0) {
			fprintf(stderr, "password prompt.\n");
			state = STATE_FEED_PASSWORD;
			tc->drain_data = 1;
		}
		break;
	case STATE_PROMPT_TOKEN:
		if (memcmp(prompt + size - sizeof(PROMPT_TOKEN), PROMPT_TOKEN, sizeof(PROMPT_TOKEN) - 1) == 0) {
			state = STATE_FEED_TOKEN;
		}
		break;
	default:
		break;
	}
	return -1;
}

int trace_write(struct trace_context *tc, uintptr_t sbuf, size_t count)
{
	char buf[PAGE_SIZE];
	size_t bsize;
	ssize_t n;

	for (int offset = 0; offset < count; offset += bsize) {
		bsize = min(count - offset, PAGE_SIZE);
		n = trace_pread(tc, buf, bsize, sbuf + offset);
		if (n < 0) {
			perror("trace_pread");
			break;
		}
		if (n == 0) {
			break;
		}

		write(STDOUT_FILENO, buf, (size_t) n);
		match_prompt(tc, buf, (size_t) n);
	}

	trace_block(tc);
	tc->regs.rax = count;
	trace_commit_regs(tc);
	return SYSCALL_HANDLED;
}

void trace_read(struct user_regs_struct *regs)
{
	int sfd = (int) regs->rdi;
	uintptr_t sbuf = regs->rsi;
	size_t scount = regs->rdx;

	if (sfd != SSH_INPUT_FD) {
		return;
	}

	switch (state) {
	case STATE_FEED_PASSWORD:
		FATAL("what is password?");
		break;
	default:
		break;
	}
}

void trace_select(struct user_regs_struct *regs)
{
	// FIXME
}


int main(int argc, char *argv[])
{
	struct trace_context tc;
	int rc;
	char *new_argv[argc + 1];

	new_argv[0] = "ssh";
	for (int i = 1; i < argc; ++i) {
		new_argv[i] = argv[i];
	}
	new_argv[argc] = NULL;

	tc.tty_write = trace_write;
	rc = trace_exec(&tc, new_argv);
	if (rc < 0) {
		FATAL("Unable to start ssh: %s\n", strerror(errno));
	}
	while ((rc = trace_next(&tc)) == 0) { ;
	}
	return 0;
}