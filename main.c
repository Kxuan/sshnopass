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
#include <assert.h>
#include "otp.h"
#include "trace_context.h"
#include "util.h"
#include "base32.h"

#define PROMPT_PASSWORD "\nYour [EMAIL] password: "
#define PROMPT_TOKEN "\nYour [VPN] token: "
#define DEFAULT_CONFIG_FILE_SUFFIX "/.ssh/sshnopass_config"
struct {
	size_t len_password;
	char *password;
	size_t len_otp_key;
	uint8_t otp_key[4096];
} cfg;

static enum {
	STATE_PROMPT_PASSWORD,
	STATE_FEED_PASSWORD,
	STATE_PROMPT_TOKEN,
	STATE_FEED_TOKEN,
	STATE_DONE
} state;

static int find_str(const char *haystack, size_t len, const char *needle, int *distance)
{
	const char *h, *n;
	int d = *distance;
	int found = 0;

	h = haystack;
	n = needle + d;

	while (h - haystack < len) {
		if (*h != *n) {
			h++;
			n = needle;
		} else {
			h++;
			n++;
			if (*n == 0) {
				found = 1;
				goto out;
			}
		}
	}

out:
	*distance = (int) (n - needle);
	return found;
}

static int match_prompt(struct trace_context *tc, const char *prompt, size_t size)
{
	static int distance = 0;
	
	switch (state) {
	case STATE_PROMPT_PASSWORD:
		if (find_str(prompt, size, PROMPT_PASSWORD, &distance)) {
			state = STATE_FEED_PASSWORD;
			distance = 0;
			tc->drain_data = 1;
		}
		break;
	case STATE_PROMPT_TOKEN:
		if (find_str(prompt, size, PROMPT_TOKEN, &distance)) {
			state = STATE_FEED_TOKEN;
			distance = 0;
			tc->drain_data = 1;
		}
		break;
	default:
		break;
	}
	return -1;
}

static int on_tty_write(struct trace_context *tc, uintptr_t sbuf, size_t count)
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

		match_prompt(tc, buf, (size_t) n);
	}

	return SYSCALL_BYPASS;
}

static int on_tty_read(struct trace_context *tc, uintptr_t sbuf, size_t count)
{
	ssize_t n;

	switch (state) {
	case STATE_FEED_PASSWORD:
		if (count < cfg.len_password) {
			FATAL("Unexpected input buffer size");
		}

		trace_block(tc);
		n = trace_pwrite(tc, cfg.password, cfg.len_password, sbuf);
		if (n != cfg.len_password) {
			FATAL("Unable to feed password");
		}
		tc->regs.rax = cfg.len_password;
		trace_commit_regs(tc);
		tc->drain_data = 0;
		state = STATE_PROMPT_TOKEN;
		return SYSCALL_HANDLED;
	case STATE_FEED_TOKEN: {
		char token[7];
		if (count < 7) {
			FATAL("Unexpected input buffer size");
		}

		trace_block(tc);
		otp_totp(cfg.otp_key, cfg.len_otp_key, token);
		token[sizeof(token) - 1] = '\r';
		n = trace_pwrite(tc, token, sizeof(token), sbuf);
		if (n != sizeof(token)) {
			FATAL("Unable to feed password");
		}
		tc->regs.rax = sizeof(token);
		trace_commit_regs(tc);
		tc->drain_data = 0;
		state = STATE_DONE;
		return SYSCALL_HANDLED;
	}
	default:
		break;
	}
}

static int parse_options(int argc, char *argv[])
{
	if (argc == 1) {
		printf("Usage: %s command parameters\n"
		       "This program is used to help you input password and OTP token automatically.\n"
		       "Please see https://github.com/Kxuan/sshnopass for more information.\n",
		       argv[0]);
		exit(1);
	}
}

static int parse_config()
{
	FILE *fp;
	size_t len_cfg_path;
	int n;
	size_t t;
	ssize_t len;
	len_cfg_path = strlen(getenv("HOME")) + sizeof(DEFAULT_CONFIG_FILE_SUFFIX);
	char filename[len_cfg_path];

	n = sprintf(filename, "%s", getenv("HOME"));
	sprintf(filename + n, "%s", DEFAULT_CONFIG_FILE_SUFFIX);

	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Unexpected error while reading config file %s: %s\n", filename, strerror(errno));
		return -1;
	}

	t = 0;
	len = getline(&cfg.password, &t, fp);
	if (len <= 0 || cfg.password[len - 1] != '\n') {
		FATAL("Invalid config file");
	}
	cfg.password[len - 1] = '\r';
	cfg.len_password = (size_t) len;

	char *line = NULL;
	t = 0;
	len = getline(&line, &t, fp);
	if (len <= 0 || line[len - 1] != '\n') {
		FATAL("Invalid config file");
	}
	n = base32_decode(line, cfg.otp_key);
	if (n <= 0) {
		FATAL("Invalid config file");
	}
	cfg.len_otp_key = (size_t) n;
	free(line);
	fclose(fp);
}

int main(int argc, char *argv[])
{
	struct trace_context tc;
	int rc;
	char *new_argv[argc];

	parse_options(argc, argv);
	parse_config();

	for (int i = 0; i < argc; ++i) {
		new_argv[i] = argv[i + 1];
	}
	new_argv[argc] = NULL;

	tc.tty_write = on_tty_write;
	tc.tty_read = on_tty_read;
	rc = trace_exec(&tc, new_argv);
	if (rc < 0) {
		FATAL("trace_exec");
	}
	while (state != STATE_DONE) {
		if (trace_next(&tc) < 0) {
			FATAL("trace_next");
		}
	}

	trace_detach(&tc);
	while (1) {
		pid_t pid = waitpid(tc.pid, NULL, 0);
		if (pid < 0) {
			if (errno == EINTR) {
				continue;
			}
			FATAL("waitpid");
		}
		break;
	}
	return 0;
}