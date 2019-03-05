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
#include "trace_context.h"
#include "util.h"

static const char *prog_name = "hack_ssh_auth";

#define PROMPT_PASSWORD "\nYour [EMAIL] password: "
#define PROMPT_TOKEN "\nYour [VPN] token: "
#define DEFAULT_CONFIG_FILE_SUFFIX "/.ssh/ssh_auth_config"
struct {
	char *password;
	char *otp_key;
} cfg;

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
		if (memcmp(prompt + size - sizeof(PROMPT_TOKEN), PROMPT_TOKEN, sizeof(PROMPT_TOKEN) - 1) == 0) {
			state = STATE_FEED_TOKEN;
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
	switch (state) {
	case STATE_FEED_PASSWORD:

		FATAL("what is password?");
		break;
	default:
		break;
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
	if (cfg.password[len - 1] == '\n') {
		cfg.password[len - 1] = 0;
	}
	t = 0;
	len = getline(&cfg.otp_key, &t, fp);
	if (cfg.otp_key[len - 1] == '\n') {
		cfg.otp_key[len - 1] = 0;
	}
	fclose(fp);
}

int main(int argc, char *argv[])
{
	struct trace_context tc;
	int rc;
	char *new_argv[argc + 1];

	parse_config();

	new_argv[0] = "ssh";
	for (int i = 1; i < argc; ++i) {
		new_argv[i] = argv[i];
	}
	new_argv[argc] = NULL;

	tc.tty_write = on_tty_write;
	tc.tty_read = on_tty_read;
	rc = trace_exec(&tc, new_argv);
	if (rc < 0) {
		FATAL("Unable to start ssh: %s\n", strerror(errno));
	}
	while ((rc = trace_next(&tc)) == 0) { ;
	}
	return 0;
}