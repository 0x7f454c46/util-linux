/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2.
 *
 * Copyright (C) 2024 Dmitry Safonov <dima@arista.com>
 *
 * lsk(1) - list task's socket info
 */
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/in.h>
#include <linux/sockios.h>
#include <linux/tcp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "nls.h"
#include "c.h"
#include "closestream.h"
#include "exec_shell.h"

static void __attribute__((__noreturn__)) usage(void)
{
	fputs(USAGE_HEADER, stdout);
	fprintf(stdout, _(" %s <pid> <options>\n"),
		program_invocation_short_name);
	fprintf(stdout, _(" %s /proc/<pid>/fd/<socket> <options>\n"),
		program_invocation_short_name);

	fputs(USAGE_SEPARATOR, stdout);
	fputs(_("Show socket information from task's file descriptor.\n"), stdout);

	fputs(USAGE_OPTIONS, stdout);
	fputs(_(" -F, --fd <file-descriptor> work on a specific task's file descriptor(s)\n"), stdout);
	fputs(_(" -J, --join [command]       enter socket network namespace\n"), stdout);
	fputs(_(" -n, --ns                   show network namespace id\n"), stdout);
	fputs(_(" -N, --ns-cookie            show network namespace cookie\n"), stdout);
	fputs(_("Other printing options:\n"), stdout);
	fputs(_(" -a, --address              \n"), stdout);
	fputs(_(" -A, --address-family       the socket domain as an integer\n"), stdout);
	fputs(_(" -B, --buffer               maximum socket send/receive buffer in bytes\n"), stdout);
	fputs(_(" -P, --protocol             socket protocol as an integer\n"), stdout);
	fputs(_(" -q, --quiet                don't print the header and be less verbose\n"), stdout);
	fputs(_(" -T, --tcp                  TCP information about the socket\n"), stdout);

	fputs(USAGE_SEPARATOR, stdout);
	fprintf(stdout, USAGE_HELP_OPTIONS(6));
	fprintf(stdout, USAGE_MAN_TAIL("lsk(1)"));

	exit(EXIT_SUCCESS);
}

struct output_opts {
	uint8_t show_netns	: 1,
		show_nscookie 	: 1,
		be_quiet 	: 1,
		show_buffer	: 1,
		show_family	: 1,
		show_protocol	: 1,
		show_tcp	: 1,
		unused		: 1;
};
static struct output_opts output;

static bool output_requested(void)
{
	return output.show_netns || output.show_nscookie || output.show_buffer
	       || output.show_family || output.show_protocol || output.show_tcp;
}

struct fd_list {
	unsigned fd;
	struct fd_list *next;
};

static void free_fd_list(struct fd_list *to_free)
{
	struct fd_list *next;

	if (!to_free)
		return;

	do {
		next = to_free->next;
		free(to_free);
	} while ((to_free = next));
}

static void print_header(void)
{
	if (output.be_quiet)
		return;
	if (!output_requested())
		return;

	printf("%4s ", "FD");
	if (output.show_netns)
		printf(" %10s", "NS");
	if (output.show_nscookie)
		printf(" %10s", "NS cookie");
	if (output.show_family)
		printf(" %3s", "AF");
	if (output.show_protocol)
		printf(" %8s", "Protocol");
	if (output.show_tcp)
		printf(" %9s", "TCP state");
	if (output.show_buffer)
		printf(" %s", "SND RCV buffer size");
	putchar('\n');
}

static void print_fd(unsigned target_fd, uintmax_t netns, uint64_t ns_cookie,
		     int sk)
{
	socklen_t sz;
	int domain, protocol;

	printf("%4u:", target_fd);

	if (output.show_netns)
		printf(" %10ju", netns);
	if (output.show_nscookie)
		printf(" %10" PRIu64, ns_cookie);

	sz = sizeof(domain);
	if (getsockopt(sk, SOL_SOCKET, SO_DOMAIN, &domain, &sz) < 0)
		err(EXIT_FAILURE, _("getsockopt(SO_DOMAIN)"));
	if (getsockopt(sk, SOL_SOCKET, SO_PROTOCOL, &protocol, &sz) < 0)
		err(EXIT_FAILURE, _("getsockopt(SO_PROTOCOL)"));

	if (output.show_family)
		printf(" %3d", domain);

	if (output.show_protocol)
		printf(" %8d", protocol);

	if (output.show_tcp) {
		if (protocol != IPPROTO_TCP) {
			printf(" %9s", "-");
		} else {
			struct tcp_info ti;
			sz = sizeof(ti);
			if (getsockopt(sk, IPPROTO_TCP, TCP_INFO, &ti, &sz) < 0)
				err(EXIT_FAILURE, _("getsockopt(TCP_INFO)"));
			printf(" %9d", ti.tcpi_state);
		}
	}

	if (output.show_buffer) {
		int sndbuf, rcvbuf;

		sz = sizeof(sndbuf);
		if (getsockopt(sk, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sz) < 0)
			err(EXIT_FAILURE, _("getsockopt(SO_SNDBUF)"));
		if (getsockopt(sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &sz) < 0)
			err(EXIT_FAILURE, _("getsockopt(SO_RCVBUF)"));
		printf(" %8d %8d", sndbuf, rcvbuf);
	}

	putchar('\n');
}

static int do_pid_fd(int pid_fd, unsigned target_fd, bool join)
{
	static uint64_t old_cookie;
	static int ret = -1;
	uint64_t ns_cookie;
	struct stat sb;
	int sk, nsfd;
	socklen_t sz;

	sk = syscall(SYS_pidfd_getfd, pid_fd, target_fd, 0);
	if (sk < 0)
		err(EXIT_FAILURE, _("pidfd_getfd(%d, %u)"), pid_fd, target_fd);

	fstat(sk, &sb);
	if (!S_ISSOCK(sb.st_mode))
		errx(EXIT_FAILURE, _("fd %u is not socket"), target_fd);

	nsfd = ioctl(sk, SIOCGSKNS);
	if (nsfd < 0)
		err(EXIT_FAILURE, _("ioctl(%d, SIOCGSKNS)"), sk);

	if (fstat(nsfd, &sb) < 0)
		err(EXIT_FAILURE, _("fstat(%d)"), nsfd);

	sz = sizeof(ns_cookie);
	if (getsockopt(sk, SOL_SOCKET, SO_NETNS_COOKIE, &ns_cookie, &sz))
		err(EXIT_FAILURE, _("getsockopt(%d, SO_NETNS_COOKIE)"), sk);

	if (join && output.be_quiet)
		goto no_print;

	print_fd(target_fd, (uintmax_t)sb.st_ino, ns_cookie, sk);

no_print:
	if (ret < 0) { /* first time in the function */
		ret = nsfd;
		old_cookie = ns_cookie;
	} else {
		close(nsfd);
		if (join && old_cookie != ns_cookie)
			err(EXIT_FAILURE, _("Sockets of the task belong to different network namespaces, you need to specify FD to --join"));
	}

	close(sk);
	return ret;
}

static char *get_optarg(int argc, char *argv[])
{
	if (optarg)
		return optarg;
	if (optind >= argc)
		return NULL;
	if (argv[optind][0] == '-')
		return NULL;
	return argv[optind++];
}

int main(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "buffer", no_argument, NULL, 'B'},
		{ "fd", required_argument, NULL, 'F' },
		{ "join", optional_argument, NULL, 'J' },
		{ "ns", no_argument, NULL, 'n' },
		{ "ns-cookie", no_argument, NULL, 'N' },
		{ "quiet", no_argument, NULL, 'q'},
		{ NULL, 0, NULL, 0 }
	};
	struct fd_list *target_fds = NULL;
	unsigned target_fd;
	bool target_fd_set = false;
	pid_t target_pid;
	char *opt_join_cmd = NULL;
	bool opt_join = false;
	int c, pidfd, nsfd = -1;
	char *endptr;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	if (argc < 2)
		errx(EXIT_FAILURE, _("No target PID specified nor /proc path"));

	errno = 0;
	target_pid = strtol(argv[1], &endptr, 10);
	if (!errno && *endptr == '\0') {
		if (target_pid <= 0)
			errx(EXIT_FAILURE, _("No idea what to do with PID = %d"), target_pid);
	} else if (sscanf(argv[1], "/proc/%d/fd/%u", &target_pid, &target_fd) == 2) {
		if (target_pid <= 0)
			errx(EXIT_FAILURE, _("No idea what to do with PID = %d"), target_pid);
		target_fd_set = true;
	} else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--helpdisplay")) {
		usage();
	} else if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--versiondisplay")) {
		print_version(EXIT_SUCCESS);
	} else {
		errx(EXIT_FAILURE, _("Can't parse PID or /proc path: `%s'"), argv[1]);
	}

	optind = 2;
	while ((c = getopt_long(argc, argv, "+ABF:J::nNPqTVh", longopts, NULL)) != -1) {
		switch (c) {
		case 'A':
			output.show_family = 1;
			break;
		case 'B':
			output.show_buffer = 1;
			break;
		case 'F':
			struct fd_list *tmp = target_fds;

			if (target_fd_set)
				errx(EXIT_FAILURE, _("Full /proc/%d/fd/%u path can't be used with other --fd=%s"),
				    target_pid, target_fd, optarg);

			target_fds = malloc(sizeof(*target_fds));
			if (!target_fds) {
				free_fd_list(tmp);
				err(EXIT_FAILURE, _("Can not allocate memory"));
			}

			errno = 0;
			target_fds->next = tmp;
			target_fds->fd = strtol(optarg, &endptr, 10);
			if (errno || *endptr != '\0') {
				free_fd_list(target_fds);
				err(EXIT_FAILURE, _("Can't parse FD argument `%s'"), optarg);
			}
			break;
		case 'J':
			optarg = get_optarg(argc, argv);
			if (optarg && opt_join_cmd)
				errx(EXIT_FAILURE, _("There was already `%s' command specified besides `%s'"), opt_join_cmd, optarg);
			else if (optarg)
				opt_join_cmd = optarg;
			opt_join = true;
			break;
		case 'n':
			output.show_netns = 1;
			break;
		case 'N':
			output.show_nscookie = 1;
			break;
		case 'P':
			output.show_protocol = 1;
			break;
		case 'q':
			output.be_quiet = 1;
			break;
		case 'T':
			output.show_tcp = 1;
			break;
		case 'h':
			usage();
		case 'V':
			print_version(EXIT_SUCCESS);
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}

	if (optind < argc)
		errx(EXIT_FAILURE, _("Unknown option %s"), argv[optind]);

	if (opt_join) {
		if (output.be_quiet && output_requested())
			errx(EXIT_FAILURE, _("Can't be quiet on --join as output requested by other options"));
		if (target_fds && target_fds->next)
			errx(EXIT_FAILURE, _("Multiple fds specified: %d, %d, which netns to --join?"),
			    target_fds->fd, target_fds->next->fd);
	} else {
		if (!output_requested())
			errx(EXIT_FAILURE, _("Nothing to show - choose appropriate option"));
	}

	pidfd = syscall(SYS_pidfd_open, target_pid, 0);
	if (pidfd < 0)
		err(EXIT_FAILURE, _("Can't pidfd_open() for %d"), target_pid);

	print_header();

	if (target_fd_set) {
		nsfd = do_pid_fd(pidfd, target_fd, opt_join);
	} else if (target_fds) {
		struct fd_list *f = target_fds;

		do {
			nsfd = do_pid_fd(pidfd, f->fd, opt_join);
			f = f->next;
		} while (f);
	} else {
		char buf[PATH_MAX];
		struct dirent *i;
		DIR *procfd;

		snprintf(buf, PATH_MAX, "/proc/%d/fd/", target_pid);
		procfd = opendir(buf);
		if (!procfd)
			err(EXIT_FAILURE, _("Failed to open %s"), buf);

		while ((i = readdir(procfd))) {
			char lnk[PATH_MAX] = {};

			if (i->d_type != DT_LNK)
				continue;

			snprintf(buf, PATH_MAX, "/proc/%d/fd/%s",
				 target_pid, i->d_name);
			if (readlink(buf, lnk, PATH_MAX) < 0)
				err(EXIT_FAILURE, _("Failed to readlink %s"), buf);

			if (strncmp(lnk, "socket:[", 8))
				continue;

			errno = 0;
			target_fd = strtoul(i->d_name, &endptr, 10);
			if (errno || *endptr != '\0')
				err(EXIT_FAILURE, _("Can't parse FD: `%s'"), i->d_name);
			nsfd = do_pid_fd(pidfd, target_fd, opt_join);
		}
		closedir(procfd);
		if (nsfd < 0 && opt_join)
			err(EXIT_FAILURE, _("Target process has no sockets to --join"));
	}

	close(pidfd);
	free_fd_list(target_fds);

	if (opt_join) {
		if (setns(nsfd, CLONE_NEWNET) < 0)
			err(EXIT_FAILURE, _("setns(%d)"), nsfd);
		close(nsfd);

		if (opt_join_cmd)
			return system(opt_join_cmd);
		exec_shell();
	}
	return 0;
}
