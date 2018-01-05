/*
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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>

#include "trace-local.h"
#include "trace-msg.h"

static bool create_fifos;

static char *append_cpu(char **cpus, char *cpu, int len, int *size, int i)
{
	char *new;

	new = realloc(*cpus, (*size) + len + !!i + 1);
	if (!new) {
		free(*cpus);
		perror("realloc");
		return NULL;
	}
	*cpus = new;
	if (i)
		sprintf((*cpus) + (*size), ",%s", cpu);
	else
		strcpy(*cpus, cpu);

	*size += len + !!i;

	return *cpus;
}

static char *make_cpu_string(int nr_cpus, const char *domain)
{
	char *name;
	char *cpus = NULL;
	int size = 0;
	int len;
	int i;

	for (i = 0; i < nr_cpus; i++) {
		len = asprintf(&name, TRACE_PATH_DOMAIN_CPU, domain, i);
		if (len < 0) {
			perror("asprintf");
			free(cpus);
			return NULL;
		}
		cpus = append_cpu(&cpus, name, len, &size, i);
		free(name);
	}

	return cpus;
}

static char *find_cpu_fifos(const char *domain)
{
	struct stat st;
	char *cpus = NULL;
	char *name;
	char *ptr;
	int size = 0;
	int len;
	int ret;
	int i;

	for (i = 0; ; i++) {
		len = asprintf(&name, TRACE_PATH_DOMAIN_CPU_I, domain, i);
		if (len < 0) {
			perror("asprintf");
			free(cpus);
			return NULL;
		}

		ret = stat(name, &st);
		if (ret < 0 || !S_ISFIFO(st.st_mode))
			break;

		/* Cut off the ".in" */
		ptr = strstr(name, ".in");
		*ptr = 0;
		cpus = append_cpu(&cpus, name, strlen(name), &size, i);
		free(name);
	}
	return cpus;
}

static char **make_cpu_list(int *nr_cpus, char *cpus)
{
	char **cpu_list;
	char *str = cpus - 1;
	int cnt = *nr_cpus;
	int i;

	if (!cnt) {
		if (!cpus)
			return NULL;
		do {
			str++;
			str = strstr(str, ",");
			cnt++;
		} while (str);
	}

	cpu_list = calloc(cnt, sizeof(*cpu_list));
	if (!cpu_list)
		return NULL;

	str = strtok(cpus, ",");
	for (i = 0; i < cnt; i++) {
		cpu_list[i] = strdup(str);
		if (!cpu_list[i])
			/* TODO clean up */
			return NULL;
		str = strtok(NULL, ",");
		if (!str) {
			if (i != cnt - 1) {
				warning("Expected %d strings but only have %d\n",
					cnt, i);
				cnt = i;
				break;
			}
		}
	}
	*nr_cpus = cnt;
	return cpu_list;
}

static char *make_fifo_path(const char *file, const char *append)
{
	char buf[PATH_MAX];
	char *fifo;
	char *prefix = NULL;
	int ret;

	if (file[0] != '/') {
		prefix = getcwd(buf, PATH_MAX);
		if (!prefix) {
			perror("getwd");
			return NULL;
		}
	}

	ret = asprintf(&fifo, "%s%s%s%s", prefix ? prefix : "",
		       prefix ? "/" : "", file, append);
	if (ret < 0) {
		perror("asprintf");
		return NULL;
	}

	return fifo;
}

static int create_dirs(const char *path, const struct group *group, int perm, bool isfile)
{
	struct stat st;
	char *tmppath;
	char *dir;
	int  ret;

	/* '/' better exist! */
	if (strcmp(path, "/") == 0)
		return 0;

	tmppath = strdup(path);
	if (!tmppath)
		return -ENOMEM;

	dir = dirname(tmppath);
	ret = stat(dir, &st);
	if (ret < 0) {
		ret = create_dirs(dir, group, perm, false);
		free(tmppath);
		if (ret < 0)
			return ret;
		tmppath = NULL;

	} else if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;

	free(tmppath);

	if (isfile)
		return 0;

	ret = mkdir(path, perm);
	if (!ret && group)
		if (chown(path, -1, group->gr_gid) < 0)
			warning("Could not change group of %s", path);
	return ret;
}

static int make_fifo(const char *agent, const char *append,
		     const struct group *group, int perm)
{
	struct stat st;
	int dir_perm = perm;
	char *file;
	int ret;
	int i;

	/* Set x in dir_perm for when w is set in perm */
	for (i = 0; i < 3; i++) {
		if (perm & (1 << (i*3+1)))
			dir_perm |= 1 << (i*3);
	}
	ret = create_dirs(agent, group, dir_perm, true);
	if (ret < 0) {
		warning("Can not create path for %s\n", agent);
		return ret;
	}

	file = make_fifo_path(agent, append);
	if (!file)
		return -1;

	ret = stat(file, &st);
	if (!ret) {
		free(file);
		/* Already there? */
		if (S_ISFIFO(st.st_mode))
			return 0;
		warning("%s exists but is not a FIFO\n", file);
		return -1;
	}

	ret = create_dirs(file, group, dir_perm, true);
	if (ret < 0)
		return ret;
	ret = mkfifo(file, perm);
	if (ret < 0) {
		free(file);
		perror("mkfifo");
		return ret;
	}

	if (group)
		if (chown(file, -1, group->gr_gid) < 0)
			warning("Could not change group of %s", file);

	free(file);

	return 0;
}

static int make_fifos(const char *domain, const char *agent, int nr_cpus,
		      char * const *cpu_list, const struct group *group,
		      int perm)
{
	int ret;
	int i;

	ret = make_fifo(agent, ".in", group, perm);
	if (ret < 0)
		return ret;

	ret = make_fifo(agent, ".out", group, perm);
	if (ret < 0)
		return ret;

	if (!nr_cpus) {
		warning("No cpu count specified. No CPU FIFOs made");
		return 0;
	}

	for (i = 0; i < nr_cpus; i++) {
		ret = make_fifo(cpu_list[i], ".in", group, perm);
		if (ret < 0)
			break;

		ret = make_fifo(cpu_list[i], ".out", group, perm);
		if (ret < 0)
			break;
	}

	return ret;
}

static int test_fifo(const char *agent, const char *append)
{
	struct stat st;
	char *file;
	int ret;

	file = make_fifo_path(agent, append);
	if (!file)
		return -1;

	ret = stat(file, &st);

	if (ret < 0 || !S_ISFIFO(st.st_mode)) {
		warning("%s does not exist or is not a FIFO", file);
		free(file);
		return -1;
	}
	free(file);

	return 0;
}

static int test_fifos(const char *domain, const char *agent, int nr_cpus,
		      char * const *cpu_list)
{
	int ret;
	int i;

	ret = test_fifo(agent, ".in");
	if (ret < 0)
		return ret;

	ret = test_fifo(agent, ".out");
	if (ret < 0)
		return ret;

	if (!nr_cpus) {
		warning("No cpu count specified.");
		return 0;
	}

	for (i = 0; i < nr_cpus; i++) {
		ret = test_fifo(cpu_list[i], ".in");
		if (ret < 0)
			break;

		ret = test_fifo(cpu_list[i], ".out");
		if (ret < 0)
			break;
	}

	return ret;
}

static int connect_guest(const char *domain, const char *agent,
			 int nr_cpus, char **cpu_list)
{
	struct tracecmd_msg_handle *msg_handle;
	int ret;
	int fd;

	fd = tracecmd_connect_to_socket(TRACE_MRG_SOCK);
	if (fd < 0)
		die("Can't connect to %s\n", TRACE_MRG_SOCK);

	msg_handle = tracecmd_msg_handle_alloc(fd, TRACECMD_MSG_FL_MANAGER);

	ret = tracecmd_msg_connect_guest(msg_handle, domain, agent,
					 nr_cpus, cpu_list);

	tracecmd_msg_handle_close(msg_handle);

	return ret;
}

enum {
	OPT_debug	= 255,
};

void trace_connect (int argc, char **argv)
{
	struct group *group = NULL;
	char **cpu_list;
	char agent_buf[PATH_MAX + 1];
	char *domain;
	char *agent = NULL;
	char *cpus = NULL;
	char *cpu_str = NULL;
	int cpu_count = 0;
	int nr_cpus = 0;
	int perm = 0640;
	int ret;
	int c;
	int i;

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help", no_argument, NULL, '?'},
			{"debug", no_argument, NULL, OPT_debug},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "hfa:c:C:p:g:",
			long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'f':
			create_fifos = true;
			break;
		case 'a':
			agent = optarg;
			break;
		case 'c':
			cpu_count = atoi(optarg);
			break;
		case 'C':
			cpus = optarg;
			break;
		case 'p':
			perm = strtol(optarg, NULL, 0);
			break;
		case 'g':
			group = getgrnam(optarg);
			if (!group)
				pdie("group %s does not exist", optarg);
			break;
		case OPT_debug:
			debug = 1;
			break;
		default:
			usage(argv);
		}
	}

	if ((argc - optind) < 2)
		usage(argv);

	domain = argv[optind + 1];

	if (!agent) {
		snprintf(agent_buf, PATH_MAX, VIRT_TRACE_CTL_FIFO, domain);
		agent_buf[PATH_MAX] = 0;
		agent = agent_buf;
	}

	if (cpus) {
		cpu_str = strdup(cpus);
		if (!cpu_str)
			die("Unable to copy cpus");
	} else if (cpu_count) {
		cpu_str = make_cpu_string(cpu_count, domain);
		if (!cpu_str)
			die("Unable to make cpu string");
	} else
		cpu_str = find_cpu_fifos(domain);

	if (cpu_str) {
		cpu_list = make_cpu_list(&nr_cpus, cpu_str);
		if (cpu_count > nr_cpus)
			cpu_count = nr_cpus;
	}

	if (create_fifos) {
		mode_t mask;

		mask = umask(0);
		ret = make_fifos(domain, agent, nr_cpus, cpu_list, group, perm);
		umask(mask);
		if (ret < 0)
			exit(ret);
	}

	ret = test_fifos(domain, agent, nr_cpus, cpu_list);
	if (ret < 0)
		exit(-1);

	/* Everything looks OK, let's connect to the server */
	connect_guest(domain, agent, nr_cpus, cpu_list);

	for (i = 0; i < nr_cpus; i++)
		free(cpu_list[i]);
	free(cpu_list);
	free(cpu_str);

	exit(0);
}
