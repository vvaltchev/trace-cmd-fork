/*
 * Copyright (C) 2016 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2018 VMware Inc, Steven Rostedt <rostedt@goodmis.org>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trace-local.h"
#include "trace-msg.h"


static bool virt;

static struct tracecmd_msg_handle *setup_network(const char *host)
{
	return NULL;
}

static struct tracecmd_msg_handle *
communicate_with_listener_virt_agent(int fd, int cpu_count)
{
	struct tracecmd_msg_handle *msg_handle;

	msg_handle = tracecmd_msg_handle_alloc(fd,
					TRACECMD_MSG_FL_CLIENT |
					TRACECMD_MSG_FL_VIRT |
					TRACECMD_MSG_FL_AGENT);
	if (!msg_handle)
		die("Failed to allocate message handle");

	if (tracecmd_msg_connect_to_server(msg_handle) < 0)
		die("Cannot communicate with server");

	if (tracecmd_msg_agent_connect(msg_handle, cpu_count) < 0)
		die("Cannot connect to server");

	return msg_handle;
}

static int test_cpu_devices(int cpu_count)
{
	struct stat st;
	char buf[PATH_MAX + 1];
	int ret;
	int i;

	for (i = 0; i < cpu_count; i++) {
		snprintf(buf, PATH_MAX, TRACE_PATH_CPU, i);
		buf[PATH_MAX] = 0;
		ret = stat(buf, &st);
		if (ret < 0 || !S_ISCHR(st.st_mode))
			break;
	}
	return i;
}

static struct tracecmd_msg_handle *setup_virtio(int cpu_count)
{
	int fd;

	cpu_count = test_cpu_devices(cpu_count);
	if (!cpu_count)
		die("No CPU devices found");

	fd = open(AGENT_CTL_PATH, O_RDWR);
	if (fd < 0)
		die("Cannot open %s", AGENT_CTL_PATH);

	return communicate_with_listener_virt_agent(fd, cpu_count);
}

enum {
	OPT_virt	= 254,
	OPT_debug	= 255,
};

void trace_agent(int argc, char **argv)
{
	struct tracecmd_msg_handle *msg_handle;
	char *host = NULL;
	int cpu_count;
	int c;

	for (;;) {
		int option_index = 0;
		const char *opts;
		static struct option long_options[] = {
			{"virt", no_argument, NULL, OPT_virt},
			{"debug", no_argument, NULL, OPT_debug},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		opts = "+hN:";
		c = getopt_long (argc-1, argv+1, opts, long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'N':
			if (virt)
				die("-N can not be used with --virt");
			host = optarg;
			break;
		case OPT_virt:
			if (host)
				die("--virt can not be used with -N");
			virt = true;
			break;
		case OPT_debug:
			debug = 1;
			break;
		default:
			usage(argv);
		}
	}

	if (!host && !virt) {
		printf("must specify --virt or -N\n");
		usage(argv);
	}

	cpu_count = count_cpus();

	if (host)
		msg_handle = setup_network(host);
	else
		msg_handle = setup_virtio(cpu_count);

	if (!msg_handle)
		exit(-1);

	return;
}
