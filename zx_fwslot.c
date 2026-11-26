// SPDX-License-Identifier: GPL-2.0-only
/*
 * zx-fwslot - flash and select ZX279133 (ZTE F627) firmware banks without the
 * vendor upgrade daemons, for the UART lab shell.
 *
 * Mirrors the vendor fw_flashing path for a plain single-FIT package on a
 * non-secure board (reverse engineered from the V32.AA1.04 binaries):
 *   - the running bank comes from the U-Boot cmdline / /proc/zxic/versionstates;
 *   - the other bank is erased completely, skipping bad blocks;
 *   - package bytes [0, 0x1e0 + FIT) go to bank offset 0, skipping bad blocks
 *     and marking blocks bad when a write fails;
 *   - the "others" partition holds "Key=0x%08x," text in its first 0x1000
 *     bytes; Image<N>Status=0xffffffff and BootImageNum=<N> select the bank.
 * U-Boot (zxboot) boots BootImageNum after checking the header magic, the
 * header CRC32 and the FIT CRC32, and tries the other bank once on failure.
 *
 * Adapted from the SR1010 zte-fwslot tool (MTD helpers and test approach); the
 * package format and bank selection are specific to the ZX279133.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mtd/mtd-user.h>

#define PKG_HDR		0x1e0
#define BANK_SIZE	0x2000000u
#define OTHERS_TEXT	0x1000
#define OTHERS_ERASE	0x80000u
#define IMAGE_STATUS_NEW 0xffffffffu

static const uint8_t pkg_magic[16] = {
	0x99,0x99,0x99,0x99, 0x44,0x44,0x44,0x44,
	0x55,0x55,0x55,0x55, 0xaa,0xaa,0xaa,0xaa,
};
/* Absolute flash offsets, also recorded at header 0x70 and 0x80. */
static const uint32_t bank_start[2] = { 0x200000, 0x2200000 };

static uint32_t crc_table[256];

static void crc_init(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;

		for (int k = 0; k < 8; k++)
			c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
		crc_table[i] = c;
	}
}

static uint32_t crc32_update(uint32_t c, const uint8_t *p, size_t n)
{
	while (n--)
		c = crc_table[(c ^ *p++) & 0xff] ^ (c >> 8);
	return c;
}

static uint32_t crc32(const uint8_t *p, size_t n)
{
	return crc32_update(0xffffffffu, p, n) ^ 0xffffffffu;
}

static uint32_t rd32(const uint8_t *p, size_t o)
{
	return p[o] | p[o + 1] << 8 | p[o + 2] << 16 | (uint32_t)p[o + 3] << 24;
}

static void fail(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void fail(const char *fmt, ...)
{
	va_list ap;

	fputs("zx-fwslot: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static bool all_ff(const uint8_t *p, size_t n)
{
	while (n--)
		if (*p++ != 0xff)
			return false;
	return true;
}

/* Read a small text file through open(2); NUL-terminated, NULL if absent. */
static char *read_text(const char *path)
{
	static char buf[8192];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n, len = 0;

	if (fd < 0)
		return NULL;
	while (len < (ssize_t)sizeof(buf) - 1 &&
	       (n = read(fd, buf + len, sizeof(buf) - 1 - len)) > 0)
		len += n;
	close(fd);
	buf[len] = 0;
	return buf;
}

/* ---------------------------------------------------------------- MTD --- */

struct mtd {
	int fd, index;
	const char *name;
	struct mtd_info_user info;
};

static int mtd_index_by_name(const char *name)
{
	char *text = read_text("/proc/mtd"), *line, *save = NULL;
	char quoted[64];
	int found = -1;

	if (!text)
		fail("cannot read /proc/mtd");
	snprintf(quoted, sizeof(quoted), "\"%s\"", name);
	for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		int idx;
		size_t len = strlen(line), qlen = strlen(quoted);

		if (sscanf(line, "mtd%d:", &idx) == 1 && len >= qlen &&
		    !strcmp(line + len - qlen, quoted)) {
			if (found >= 0)
				fail("more than one MTD partition is named %s", name);
			found = idx;
		}
	}
	if (found < 0)
		fail("no MTD partition named %s in /proc/mtd", name);
	return found;
}

/* Partition offset from sysfs (Linux >= 4.19 exposes it); -1 if unknown. */
static long long mtd_sysfs_offset(int index)
{
	char path[64], *text;

	snprintf(path, sizeof(path), "/sys/class/mtd/mtd%d/offset", index);
	text = read_text(path);
	return text ? strtoll(text, NULL, 0) : -1;
}

static void mtd_open(struct mtd *m, const char *name, bool writable,
		     uint32_t want_size, long long want_offset)
{
	char path[32];
	struct stat st;
	long long ofs;

	m->name = name;
	m->index = mtd_index_by_name(name);
	snprintf(path, sizeof(path), "/dev/mtd%d", m->index);
	m->fd = open(path, (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC);
	if (m->fd < 0)
		fail("open %s (%s): %s", path, name, strerror(errno));
	if (fstat(m->fd, &st) || !S_ISCHR(st.st_mode))
		fail("%s is not a character device", path);
	if (ioctl(m->fd, MEMGETINFO, &m->info) < 0)
		fail("MEMGETINFO on %s: %s", path, strerror(errno));
	if (m->info.type != MTD_NANDFLASH && m->info.type != MTD_MLCNANDFLASH)
		fail("%s (%s) is not NAND", path, name);
	if (!m->info.erasesize || !m->info.writesize ||
	    m->info.erasesize % m->info.writesize || m->info.size % m->info.erasesize ||
	    OTHERS_TEXT % m->info.writesize || OTHERS_ERASE % m->info.erasesize)
		fail("%s (%s) has an unexpected geometry", path, name);
	if (want_size && m->info.size != want_size)
		fail("%s (%s) is %#x bytes, expected %#x", path, name, m->info.size, want_size);
	ofs = mtd_sysfs_offset(m->index);
	if (want_offset >= 0 && ofs >= 0 && ofs != want_offset)
		fail("%s (%s) starts at %#llx, expected %#llx", path, name, ofs, want_offset);
}

static bool mtd_bad(struct mtd *m, uint32_t ofs)
{
	long long o = ofs;
	int r = ioctl(m->fd, MEMGETBADBLOCK, &o);

	if (r < 0)
		fail("MEMGETBADBLOCK %s@%#x: %s", m->name, ofs, strerror(errno));
	return r > 0;
}

static void mtd_mark_bad(struct mtd *m, uint32_t ofs)
{
	long long o = ofs;

	fprintf(stderr, "  marking %s block %#x bad\n", m->name, ofs);
	if (ioctl(m->fd, MEMSETBADBLOCK, &o) < 0)
		fprintf(stderr, "  MEMSETBADBLOCK failed: %s\n", strerror(errno));
}

static int mtd_erase_block(struct mtd *m, uint32_t ofs)
{
	struct erase_info_user e = { .start = ofs, .length = m->info.erasesize };

	ioctl(m->fd, MEMUNLOCK, &e);
	return ioctl(m->fd, MEMERASE, &e);
}

static void preadn(struct mtd *m, void *buf, size_t n, uint32_t ofs)
{
	if (pread(m->fd, buf, n, ofs) != (ssize_t)n)
		fail("read %s@%#x: %s", m->name, ofs, strerror(errno));
}

/*
 * Read @len bytes of the logical stream that starts at the first good block,
 * skipping bad blocks, as U-Boot's nand read and the vendor flasher do.
 * Returns false if the partition ends first.
 */
static bool mtd_read_logical(struct mtd *m, uint8_t *buf, size_t len)
{
	uint32_t bs = m->info.erasesize, ofs = 0;

	while (len) {
		size_t n = len < bs ? len : bs;

		if (ofs >= m->info.size)
			return false;
		if (mtd_bad(m, ofs)) {
			ofs += bs;
			continue;
		}
		preadn(m, buf, n, ofs);
		buf += n;
		len -= n;
		ofs += bs;
	}
	return true;
}

/* Erase the first @count good blocks (all when 0); failed ones become bad. */
static void mtd_erase_logical(struct mtd *m, uint32_t count)
{
	uint32_t bs = m->info.erasesize, done = 0;

	for (uint32_t ofs = 0; ofs < m->info.size && (!count || done < count); ofs += bs) {
		if (mtd_bad(m, ofs))
			continue;
		if (mtd_erase_block(m, ofs) < 0) {
			fprintf(stderr, "  erase failed at %s@%#x: %s\n", m->name, ofs, strerror(errno));
			mtd_mark_bad(m, ofs);
			continue;
		}
		done++;
	}
	if (count && done < count)
		fail("%s: only %u of %u blocks could be erased", m->name, done, count);
}

/*
 * Write @len bytes as a logical stream from the first good block. The target
 * must be erased. The tail of the last block is padded to a page with 0xff.
 */
static void mtd_write_logical(struct mtd *m, const uint8_t *data, size_t len)
{
	uint32_t bs = m->info.erasesize, ws = m->info.writesize, ofs = 0;
	uint8_t *chunk = malloc(bs);

	if (!chunk)
		fail("out of memory");
	while (len) {
		size_t n = len < bs ? len : bs;
		size_t padded = (n + ws - 1) / ws * ws;

		if (ofs >= m->info.size)
			fail("%s: ran out of good blocks", m->name);
		if (mtd_bad(m, ofs)) {
			fprintf(stderr, "  skipping bad block %s@%#x\n", m->name, ofs);
			ofs += bs;
			continue;
		}
		memset(chunk, 0xff, padded);
		memcpy(chunk, data, n);
		if (pwrite(m->fd, chunk, padded, ofs) != (ssize_t)padded) {
			fprintf(stderr, "  write failed at %s@%#x: %s\n", m->name, ofs, strerror(errno));
			mtd_mark_bad(m, ofs);
			ofs += bs;
			continue;
		}
		data += n;
		len -= n;
		ofs += bs;
	}
	free(chunk);
}

/* ------------------------------------------------------------ package --- */

struct package {
	uint8_t *data;
	size_t size;	/* file size */
	size_t span;	/* bytes the vendor writes: 0x1e0 + FIT */
};

/* What zxboot checks in the header before reading the FIT at 0x1e0. */
static const char *boot_header_problem(const uint8_t *h)
{
	uint32_t fit_len = rd32(h, 0x58);

	if (memcmp(h, pkg_magic, 16))
		return "missing package magic";
	if (rd32(h, 0x10))
		return "unsupported version header offset";
	if (rd32(h, 0x110) != crc32(h + 0x14, 0x110 - 0x14))
		return "version header CRC mismatch";
	if (fit_len < 40 || fit_len > BANK_SIZE - PKG_HDR)
		return "bad FIT length";
	return NULL;
}

/*
 * The plain single-FIT layout produced by build_ota.py; the same rules as its
 * parse(), plus the bank table the vendor flasher reads from the header.
 * Stricter than zxboot: stock bank 0 with an appended component boots but is
 * not accepted as a package.
 */
static const char *header_problem(const uint8_t *h, size_t avail)
{
	uint32_t fit_len = rd32(h, 0x58), end;
	const char *why = boot_header_problem(h);

	if (why)
		return why;
	if (rd32(h, 0x18) || rd32(h, 0x50) != 1 || memcmp(h + 0x148, "133", 4))
		return "not a plain single-version ZX279133 header";
	if (rd32(h, 0x64) || rd32(h, 0x6c) || !all_ff(h + 0x178, PKG_HDR - 0x178))
		return "additional components are not supported";
	for (int i = 0xc8; i < 0xf8; i++)
		if (h[i])
			return "additional components are not supported";
	if (rd32(h, 0x70) != bank_start[0] || rd32(h, 0x74) != BANK_SIZE ||
	    rd32(h, 0x80) != bank_start[1] || rd32(h, 0x84) != BANK_SIZE)
		return "unexpected bank table in header";
	end = (PKG_HDR + fit_len + 15) & ~15u;
	if (rd32(h, 0x5c) != PKG_HDR || rd32(h, 0x54) != end || rd32(h, 0x68) != end || (avail && avail < end))
		return "inconsistent payload ranges";
	return NULL;
}

static const char *fit_problem(const uint8_t *h, const uint8_t *fit)
{
	uint32_t len = rd32(h, 0x58);

	if (memcmp(fit, "\xd0\x0d\xfe\xed", 4) ||
	    ((uint32_t)fit[4] << 24 | fit[5] << 16 | fit[6] << 8 | fit[7]) != len)
		return "bad FIT magic or size";
	if (crc32(fit, len) != rd32(h, 0x60))
		return "FIT CRC mismatch";
	return NULL;
}

static void package_load(struct package *p, const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	struct stat st;
	const char *why;
	size_t got = 0;

	if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode))
		fail("%s: not a readable regular file", path);
	if (st.st_size <= PKG_HDR || st.st_size > BANK_SIZE)
		fail("%s: size %lld is not a ZX279133 bank package", path, (long long)st.st_size);
	p->size = st.st_size;
	p->data = malloc(p->size);
	if (!p->data)
		fail("out of memory for %zu bytes", p->size);
	while (got < p->size) {
		ssize_t n = read(fd, p->data + got, p->size - got);

		if (n <= 0)
			fail("%s: read error", path);
		got += n;
	}
	close(fd);
	why = header_problem(p->data, p->size);
	if (why)
		fail("%s: %s", path, why);
	p->span = PKG_HDR + rd32(p->data, 0x58);
	if (p->size != rd32(p->data, 0x54) || !all_ff(p->data + p->span, p->size - p->span))
		fail("%s: unexpected data after the FIT", path);
	why = fit_problem(p->data, p->data + PKG_HDR);
	if (why)
		fail("%s: %s", path, why);
}

static void print_header(const uint8_t *h)
{
	printf("version=\"%.44s\" build=\"%.16s\" fit=%#x crc=%08x",
	       (const char *)h + 0x24, (const char *)h + 0x168, rd32(h, 0x58), rd32(h, 0x60));
}

/* --------------------------------------------------------------- banks --- */

/*
 * Check a bank the way zxboot does on a non-secure board: header magic and
 * CRC, then the FIT CRC over the logical stream. Returns NULL if bootable.
 * U-Boot also scans forward block by block for the magic; this tool always
 * writes the header to the first good block, so only that block is checked.
 */
static const char *bank_problem(struct mtd *m, uint8_t *hdr)
{
	const char *why;
	uint8_t *buf;
	size_t span;

	if (!mtd_read_logical(m, hdr, PKG_HDR))
		return "no good block";
	if (all_ff(hdr, PKG_HDR))
		return "empty";
	why = boot_header_problem(hdr);
	if (why)
		return why;
	span = PKG_HDR + rd32(hdr, 0x58);
	buf = malloc(span);
	if (!buf)
		fail("out of memory");
	why = mtd_read_logical(m, buf, span) ? fit_problem(hdr, buf + PKG_HDR) :
					     "payload runs past the end of the bank";
	free(buf);
	return why;
}

static void bank_open(struct mtd *m, int bank, bool writable)
{
	static const char *const names[2] = { "kernel0", "kernel1" };

	mtd_open(m, names[bank], writable, BANK_SIZE, bank_start[bank]);
}

/* The bank U-Boot started, from the cmdline it passes and the vendor proc file. */
static int running_bank(void)
{
	char *text = read_text("/proc/cmdline"), *p;
	unsigned base, cur, s1, s2;
	int bank;

	if (!text || !(p = strstr(text, "U-Boot ")) ||
	    sscanf(p, "%*s %*s %*s %x %x %x %x", &base, &cur, &s1, &s2) != 4)
		fail("no U-Boot bank record in /proc/cmdline");
	bank = cur;
	if (cur > 1 || base != bank_start[bank])
		fail("unexpected U-Boot bank record: base %#x current %u", base, cur);
	text = read_text("/proc/zxic/versionstates");
	if (text) {
		unsigned vbase, vcur;
		char *b = strstr(text, "baseaddress"), *c = strstr(text, "current");

		if (b)
			b = strchr(b, ':');
		if (c)
			c = strchr(c, ':');
		if (!b || !c || sscanf(b + 1, "%x", &vbase) != 1 ||
		    sscanf(c + 1, "%u", &vcur) != 1)
			fail("cannot parse /proc/zxic/versionstates");
		if (vbase != base || vcur != cur)
			fail("/proc/cmdline and /proc/zxic/versionstates disagree");
	}
	return bank;
}

/* Refuse to race the vendor upgrade stack, which locks "others" over IPC. */
static void require_no_vendor_daemons(void)
{
	static const char *const names[] = { "cspd", "fw_flashing", "gpon_omci", "pc" };
	DIR *d = opendir("/proc");
	struct dirent *e;

	if (!d)
		fail("cannot list /proc");
	while ((e = readdir(d))) {
		char path[300], *comm;

		if (!isdigit((unsigned char)e->d_name[0]))
			continue;
		snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
		comm = read_text(path);
		if (!comm)
			continue;
		comm[strcspn(comm, "\n")] = 0;
		for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
			if (!strcmp(comm, names[i]))
				fail("vendor process %s (pid %s) is running; use the vendor "
				     "upgrade path on the stock system", comm, e->d_name);
	}
	closedir(d);
}

/* -------------------------------------------------------------- others --- */

struct others {
	struct mtd m;
	uint8_t text[OTHERS_TEXT];
	uint8_t *region;	/* the OTHERS_ERASE bytes the vendor erases */
};

/* Offset of "key=" at the start of the text or after ',', or -1. */
static long others_find(const uint8_t *t, const char *key)
{
	size_t k = strlen(key);

	for (size_t i = 0; i + k < OTHERS_TEXT; i++)
		if ((i == 0 || t[i - 1] == ',') && !memcmp(t + i, key, k) && t[i + k] == '=')
			return i;
	return -1;
}

static long others_get(const uint8_t *t, const char *key)
{
	long at = others_find(t, key);
	char val[11];

	if (at < 0)
		return -1;
	memcpy(val, t + at + strlen(key) + 1, 10);
	val[10] = 0;
	return strtoul(val, NULL, 16);
}

static void others_load(struct others *o, bool writable)
{
	size_t used = OTHERS_TEXT;

	mtd_open(&o->m, "others", writable, 0, -1);
	o->region = malloc(OTHERS_ERASE);
	if (!o->region)
		fail("out of memory");
	if (!mtd_read_logical(&o->m, o->region, OTHERS_ERASE))
		fail("others: not enough good blocks");
	memcpy(o->text, o->region, OTHERS_TEXT);
	while (used && o->text[used - 1] == 0xff)
		used--;
	for (size_t i = 0; i < used; i++)
		if (o->text[i] < 0x20 || o->text[i] > 0x7e)
			fail("others: unexpected byte %#x at %#zx; not touching it", o->text[i], i);
	if (used && o->text[used - 1] != ',')
		fail("others: record does not end with ','; not touching it");
	if (!all_ff(o->region + OTHERS_TEXT, OTHERS_ERASE - OTHERS_TEXT))
		fail("others: data beyond %#x would be erased; not touching it", OTHERS_TEXT);
}

/* WritePrivateProfileInt: replace "key=0x%08x," in place or append it. */
static void others_set(uint8_t *t, const char *key, uint32_t value)
{
	char item[32];
	int n = snprintf(item, sizeof(item), "%s=0x%08x,", key, value);
	long at = others_find(t, key);

	if (n <= 0 || n >= (int)sizeof(item))
		fail("others: key too long");
	if (at >= 0) {
		const uint8_t *end = memchr(t + at, ',', OTHERS_TEXT - at);

		if (!end || end - (t + at) + 1 != n)
			fail("others: existing %s entry has an unexpected width", key);
	} else {
		at = OTHERS_TEXT;
		while (at && t[at - 1] == 0xff)
			at--;
		if (at + n > OTHERS_TEXT)
			fail("others: no room for %s", key);
	}
	memcpy(t + at, item, n);
}

static void others_commit(struct others *o, const uint8_t *text)
{
	uint8_t back[OTHERS_TEXT];

	if (!memcmp(text, o->text, OTHERS_TEXT)) {
		printf("others: already up to date\n");
		return;
	}
	mtd_erase_logical(&o->m, OTHERS_ERASE / o->m.info.erasesize);
	mtd_write_logical(&o->m, text, OTHERS_TEXT);
	if (!mtd_read_logical(&o->m, back, OTHERS_TEXT) || memcmp(back, text, OTHERS_TEXT))
		fail("others: read-back mismatch");
	memcpy(o->text, text, OTHERS_TEXT);
}

static void print_others(const uint8_t *t)
{
	size_t used = OTHERS_TEXT;

	while (used && t[used - 1] == 0xff)
		used--;
	printf("others: %.*s\n", (int)used, (const char *)t);
}

/* ------------------------------------------------------------ commands --- */

static int cmd_check(const char *path)
{
	struct package p;

	package_load(&p, path);
	printf("ok: %s: ", path);
	print_header(p.data);
	printf(" bytes=%zu\n", p.size);
	return 0;
}

static int cmd_info(void)
{
	int run = running_bank();
	struct others o;
	long boot;

	others_load(&o, false);
	boot = others_get(o.text, "BootImageNum");
	printf("running bank: %d\n", run);
	printf("BootImageNum: %ld%s\n", boot,
	       boot == 0 || boot == 1 ? "" : " (missing or invalid: U-Boot uses bank 0)");
	for (int b = 0; b < 2; b++) {
		struct mtd m;
		uint8_t hdr[PKG_HDR];
		const char *why;

		bank_open(&m, b, false);
		why = bank_problem(&m, hdr);
		printf("bank %d: mtd%d ", b, m.index);
		if (why)
			printf("NOT BOOTABLE (%s)", why);
		else
			print_header(hdr);
		printf("%s%s\n", b == run ? " [running]" : "",
		       b == (boot == 1) ? " [next boot]" : "");
		close(m.fd);
	}
	print_others(o.text);
	return 0;
}

static void select_bank(struct others *o, int bank, bool new_image)
{
	uint8_t text[OTHERS_TEXT];
	char key[16];

	memcpy(text, o->text, OTHERS_TEXT);
	if (new_image) {
		snprintf(key, sizeof(key), "Image%dStatus", bank);
		others_set(text, key, IMAGE_STATUS_NEW);
	}
	others_set(text, "BootImageNum", bank);
	others_commit(o, text);
	if (others_get(o->text, "BootImageNum") != bank)
		fail("others: BootImageNum did not stick");
}

static int cmd_select(int bank)
{
	struct others o;
	struct mtd m;
	uint8_t hdr[PKG_HDR];
	const char *why;
	int run = running_bank();

	require_no_vendor_daemons();
	bank_open(&m, bank, false);
	why = bank_problem(&m, hdr);
	close(m.fd);
	if (why)
		fail("bank %d is not bootable (%s); not selecting it", bank, why);
	others_load(&o, true);
	select_bank(&o, bank, false);
	printf("ok: next boot uses bank %d (", bank);
	print_header(hdr);
	printf(")%s\n", bank == run ? ", the running bank" : "; reboot to start it");
	return 0;
}

static int cmd_flash(const char *path, bool dry_run)
{
	struct package p;
	struct others o;
	struct mtd m;
	uint8_t hdr[PKG_HDR], *back;
	const char *why;
	int run, target;

	package_load(&p, path);
	run = running_bank();
	target = run ^ 1;
	require_no_vendor_daemons();
	/* Open and validate everything before the first erase. */
	others_load(&o, !dry_run);
	bank_open(&m, target, !dry_run);
	printf("package: ");
	print_header(p.data);
	printf("\nrunning bank %d stays untouched; writing bank %d (mtd%d, %#x bytes)\n",
	       run, target, m.index, (unsigned)p.span);
	if (dry_run) {
		printf("dry run: no changes made\n");
		return 0;
	}
	printf("erasing bank %d ...\n", target);
	mtd_erase_logical(&m, 0);
	printf("writing ...\n");
	mtd_write_logical(&m, p.data, p.span);
	printf("verifying ...\n");
	back = malloc(p.span);
	if (!back)
		fail("out of memory");
	if (!mtd_read_logical(&m, back, p.span) || memcmp(back, p.data, p.span))
		fail("bank %d read-back mismatch; BootImageNum NOT changed", target);
	free(back);
	why = bank_problem(&m, hdr);
	if (why)
		fail("bank %d does not verify (%s); BootImageNum NOT changed", target, why);
	close(m.fd);
	select_bank(&o, target, true);
	printf("ok: bank %d written and selected; reboot to start it\n", target);
	return 0;
}

static int usage(void)
{
	fprintf(stderr,
		"usage: zx-fwslot info                  show banks and the boot selection\n"
		"       zx-fwslot check FILE            verify a package without touching flash\n"
		"       zx-fwslot flash [-n] FILE       write FILE to the other bank and select it\n"
		"                                       (-n: dry run, validate only)\n"
		"       zx-fwslot select 0|1            boot that bank next (after verifying it)\n"
		"       zx-fwslot switch                select the bank that is not running\n");
	return 2;
}

int main(int argc, char **argv)
{
	crc_init();
	if (argc == 2 && !strcmp(argv[1], "info"))
		return cmd_info();
	if (argc == 3 && !strcmp(argv[1], "check"))
		return cmd_check(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "flash"))
		return cmd_flash(argv[2], false);
	if (argc == 4 && !strcmp(argv[1], "flash") && !strcmp(argv[2], "-n"))
		return cmd_flash(argv[3], true);
	if (argc == 3 && !strcmp(argv[1], "select") &&
	    (!strcmp(argv[2], "0") || !strcmp(argv[2], "1")))
		return cmd_select(argv[2][0] - '0');
	if (argc == 2 && !strcmp(argv[1], "switch"))
		return cmd_select(running_bank() ^ 1);
	return usage();
}
