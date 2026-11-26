/* Raw pass-through to np.ko's msoft_debug_dev ioctl (char major 191).
 * usage: npdbg CMD [u32 ...]   CMD 0x800..0x821; args fill the 260-byte
 * buffer as u32 words; prints return value and the first N words back.
 * Env NPDBG_N = number of words to print (default 12). */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

/* npdbg mem REG COUNT: dump PPS registers (phys 0x18000000 + 4*REG) */
static int memdump(unsigned long reg, unsigned long cnt)
{
    int fd = open("/dev/mem", O_RDONLY | O_SYNC);
    unsigned long i, pa = 0x18000000UL + reg * 4, pg = pa & ~0xfffUL;
    size_t len = (pa - pg) + cnt * 4;
    volatile unsigned int *m;
    void *map;
    if (fd < 0) { perror("/dev/mem"); return 1; }
    map = mmap(0, len, PROT_READ, MAP_SHARED, fd, pg);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }
    m = (volatile unsigned int *)((char *)map + (pa - pg));
    for (i = 0; i < cnt; i++)
        printf("%05lx %08x\n", reg + i, m[i]);
    munmap(map, len);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned int buf[65];
    const char *dev = "/dev/msoft_debug_dev";
    int fd, i, n = 12, r;
    unsigned long cmd;
    if (argc < 2) {
        fprintf(stderr, "usage: %s CMD [u32...]\n", argv[0]);
        return 2;
    }
    if (argc == 4 && !strcmp(argv[1], "mem"))
        return memdump(strtoul(argv[2], 0, 0), strtoul(argv[3], 0, 0));
    if (getenv("NPDBG_N"))
        n = atoi(getenv("NPDBG_N"));
    if (n > 65)
        n = 65;
    if (access(dev, F_OK) != 0 && mknod(dev, S_IFCHR | 0600, makedev(191, 0)) != 0) {
        perror("mknod");
        return 1;
    }
    fd = open(dev, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    memset(buf, 0, sizeof buf);
    cmd = strtoul(argv[1], 0, 0);
    for (i = 2; i < argc && i - 2 < 65; i++)
        buf[i - 2] = strtoul(argv[i], 0, 0);
    r = ioctl(fd, cmd, buf);
    printf("ret=%d errno=%d", r, r < 0 ? errno : 0);
    for (i = 0; i < n; i++)
        printf(" %08x", buf[i]);
    printf("\n");
    close(fd);
    return r < 0;
}
