// SPDX-License-Identifier: GPL-2.0-only
/*
 * LD_PRELOAD shim for host tests of zx-fwslot: runs the unmodified tool
 * against plain files standing in for NAND partitions and procfs.
 *
 *   FAKE_ROOT          holds dev/mtdN, proc/..., sys/class/mtd/...
 *   FAKE_BAD           "N:0xofs,..." blocks listed in the bad block table
 *   FAKE_WRITE_FAIL    "N:0xofs,..." blocks whose program operation fails
 *   FAKE_ERASE_FAIL    "N:0xofs,..." blocks whose erase fails
 *
 * Stricter than a plain file: writes must be page aligned and may only
 * program erased (all 0xff) pages, as on real NAND. Every MTD erase/write is
 * logged to $FAKE_ROOT/oplog and rule violations to $FAKE_ROOT/violations.
 * Adapted from the zte-fwslot fakemtd.c test shim.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mtd/mtd-user.h>

#define ERASESIZE 0x20000
#define WRITESIZE 2048
#define MAXFD 1024

static int fd_dev[MAXFD];	/* mtd index + 1 of a tracked fd, else 0 */

static const char *root(void)
{
	const char *r = getenv("FAKE_ROOT");

	if (!r) {
		fprintf(stderr, "fakemtd: FAKE_ROOT is not set\n");
		exit(99);
	}
	return r;
}

static const char *map(const char *path, char *buf, size_t n)
{
	static const char *const prefix[] = { "/dev/mtd", "/proc", "/sys/class/mtd" };

	for (unsigned i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++) {
		size_t l = strlen(prefix[i]);

		if (!strncmp(path, prefix[i], l) && (path[l] == 0 || path[l] == '/' ||
						     i == 0)) {
			snprintf(buf, n, "%s%s", root(), path);
			return buf;
		}
	}
	return path;
}

static void logf_(const char *file, const char *fmt, ...)
{
	char path[512];
	va_list ap;
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", root(), file);
	f = fopen(path, "a");
	if (!f)
		return;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fclose(f);
}

static int in_list(const char *env, int dev, unsigned long long ofs)
{
	const char *p = getenv(env);

	while (p && *p) {
		int d;
		unsigned long long o;

		if (sscanf(p, "%d:%llx", &d, &o) == 2 && d == dev &&
		    ofs / ERASESIZE == o / ERASESIZE)
			return 1;
		p = strchr(p, ',');
		if (p)
			p++;
	}
	return 0;
}

static int in_badlist(int dev, unsigned long long ofs)
{
	char path[512], line[64];
	FILE *f;
	int hit = 0;

	snprintf(path, sizeof(path), "%s/badlist", root());
	f = fopen(path, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		int d;
		unsigned long long o;

		if (sscanf(line, "%d %llx", &d, &o) == 2 && d == dev &&
		    ofs / ERASESIZE == o / ERASESIZE)
			hit = 1;
	}
	fclose(f);
	return hit;
}

static int dev_of(int fd)
{
	return (fd >= 0 && fd < MAXFD) ? fd_dev[fd] - 1 : -1;
}

static ssize_t real_pwrite(int fd, const void *buf, size_t n, off_t ofs)
{
	static ssize_t (*real)(int, const void *, size_t, off_t);

	if (!real)
		real = dlsym(RTLD_NEXT, "pwrite");
	return real(fd, buf, n, ofs);
}

static int real_fstat(int fd, struct stat *st)
{
	static int (*real)(int, struct stat *);

	if (!real)
		real = dlsym(RTLD_NEXT, "fstat");
	return real(fd, st);
}

/* The partition files stand in for MTD character devices. */
int fstat(int fd, struct stat *st)
{
	int r = real_fstat(fd, st);

	if (!r && dev_of(fd) >= 0)
		st->st_mode = S_IFCHR | 0600;
	return r;
}

int open(const char *path, int flags, ...)
{
	static int (*real)(const char *, int, ...);
	char buf[512];
	mode_t mode = 0;
	int fd, idx;

	if (!real)
		real = dlsym(RTLD_NEXT, "open");
	if (flags & O_CREAT) {
		va_list ap;

		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	fd = real(map(path, buf, sizeof(buf)), flags, mode);
	if (fd >= 0 && fd < MAXFD) {
		char tail;

		fd_dev[fd] = (sscanf(path, "/dev/mtd%d%c", &idx, &tail) == 1) ? idx + 1 : 0;
	}
	return fd;
}

DIR *opendir(const char *path)
{
	static DIR *(*real)(const char *);
	char buf[512];

	if (!real)
		real = dlsym(RTLD_NEXT, "opendir");
	return real(map(path, buf, sizeof(buf)));
}

int ioctl(int fd, int req, ...)
{
	static int (*real)(int, int, ...);
	va_list ap;
	void *arg;
	int dev = dev_of(fd);

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (dev < 0) {
		if (!real)
			real = dlsym(RTLD_NEXT, "ioctl");
		return real(fd, req, arg);
	}
	switch ((unsigned)req) {
	case (unsigned)MEMGETINFO: {
		struct mtd_info_user *i = arg;
		struct stat st;

		real_fstat(fd, &st);
		memset(i, 0, sizeof(*i));
		i->type = MTD_NANDFLASH;
		i->size = st.st_size;
		i->erasesize = ERASESIZE;
		i->writesize = WRITESIZE;
		i->oobsize = 64;
		return 0;
	}
	case (unsigned)MEMGETBADBLOCK: {
		unsigned long long ofs = *(long long *)arg;

		return in_list("FAKE_BAD", dev, ofs) || in_badlist(dev, ofs);
	}
	case (unsigned)MEMSETBADBLOCK:
		logf_("badlist", "%d %llx\n", dev, *(unsigned long long *)arg);
		logf_("oplog", "markbad %d %llx\n", dev, *(unsigned long long *)arg);
		return 0;
	case (unsigned)MEMUNLOCK:
		return 0;
	case (unsigned)MEMERASE: {
		struct erase_info_user *e = arg;
		static unsigned char ff[ERASESIZE];

		memset(ff, 0xff, sizeof(ff));
		if (e->start % ERASESIZE || e->length != ERASESIZE) {
			logf_("violations", "erase %d %x+%x not one block\n", dev, e->start, e->length);
			errno = EINVAL;
			return -1;
		}
		if (in_list("FAKE_BAD", dev, e->start) || in_badlist(dev, e->start))
			logf_("violations", "erase of bad block %d %x\n", dev, e->start);
		logf_("oplog", "erase %d %x\n", dev, e->start);
		if (in_list("FAKE_ERASE_FAIL", dev, e->start)) {
			errno = EIO;
			return -1;
		}
		return real_pwrite(fd, ff, ERASESIZE, e->start) == ERASESIZE ? 0 : -1;
	}
	}
	errno = ENOTTY;
	return -1;
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t ofs)
{
	static ssize_t (*real_pread)(int, void *, size_t, off_t);
	int dev = dev_of(fd);
	unsigned char *old;

	if (!real_pread)
		real_pread = dlsym(RTLD_NEXT, "pread");
	if (dev < 0)
		return real_pwrite(fd, buf, n, ofs);
	if (ofs % WRITESIZE || n % WRITESIZE || ofs / ERASESIZE != (off_t)(ofs + n - 1) / ERASESIZE) {
		logf_("violations", "write %d %llx+%zx not page aligned or spans blocks\n",
		      dev, (unsigned long long)ofs, n);
		errno = EINVAL;
		return -1;
	}
	if (in_list("FAKE_BAD", dev, ofs) || in_badlist(dev, ofs))
		logf_("violations", "write to bad block %d %llx\n", dev, (unsigned long long)ofs);
	logf_("oplog", "write %d %llx %zx\n", dev, (unsigned long long)ofs, n);
	if (in_list("FAKE_WRITE_FAIL", dev, ofs)) {
		errno = EIO;
		return -1;
	}
	old = malloc(n);
	real_pread(fd, old, n, ofs);
	for (size_t i = 0; i < n; i++)
		if (old[i] != 0xff) {
			logf_("violations", "program over unerased data %d %llx\n",
			      dev, (unsigned long long)ofs + i);
			free(old);
			errno = EIO;
			return -1;
		}
	free(old);
	return real_pwrite(fd, buf, n, ofs);
}

ssize_t write(int fd, const void *buf, size_t n)
{
	static ssize_t (*real)(int, const void *, size_t);

	if (!real)
		real = dlsym(RTLD_NEXT, "write");
	if (dev_of(fd) >= 0) {
		logf_("violations", "unpositioned write to mtd%d\n", dev_of(fd));
		errno = EINVAL;
		return -1;
	}
	return real(fd, buf, n);
}
