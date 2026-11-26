/* ZX279133 F627: register LAN1 in the vendor netdriver, without pc/cspd. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define ETHDRIVER "/dev/ethdriver"
#define ETHMAP "/proc/capability/ethernetmac"
/* Vendor ABI encodes a 4-byte size but copies 24 and 11 bytes respectively. */
#define SET_DEV_INFO 0x40045334UL
#define ADD_DEV      0x40045302UL

struct dev_info {
    uint32_t id, switch_port, pon_port, pon_bridge, source_flow;
    uint8_t is_wan, cpu_tag, reserved[2];
};
struct add_dev {
    uint8_t id, flags;
    char name[9];
};
_Static_assert(sizeof(struct dev_info) == 24, "wrong SET_DEV_INFO size");
_Static_assert(offsetof(struct dev_info, switch_port) == 4, "wrong port offset");
_Static_assert(offsetof(struct dev_info, cpu_tag) == 21, "wrong CPU tag offset");
_Static_assert(sizeof(struct add_dev) == 11, "wrong ADD_DEV size");
_Static_assert(offsetof(struct add_dev, name) == 2, "wrong name offset");

static int fail(const char *message)
{
    fprintf(stderr, "lan1-register: %s\n", message);
    return 1;
}

static int has_expected_map(void)
{
    FILE *f = fopen(ETHMAP, "r");
    char line[160], name[16], speed[16], duplex[16], curmode[16];
    unsigned emac, mode, autoneg, port;
    int found = 0;
    if (!f) {
        perror(ETHMAP);
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%15s %u %u %15s %15s %u %15s %u", name, &emac,
                   &mode, speed, duplex, &autoneg, curmode, &port) == 8 &&
            !strcmp(name, "eth0")) {
            found = emac == 0 && mode == 7 && port == 4;
            break;
        }
    }
    fclose(f);
    return found;
}

static int is_ethdriver(const struct stat *st)
{
    return S_ISCHR(st->st_mode) && major(st->st_rdev) == 83 && minor(st->st_rdev) == 0;
}

int main(int argc, char *argv[])
{
    int fd, apply;
    struct stat st;
    struct dev_info dev = { .id = 0, .switch_port = 4 };
    struct add_dev add = { .id = 0, .flags = 0, .name = "eth0" };

    if (argc != 2 || (strcmp(argv[1], "--check") && strcmp(argv[1], "--apply"))) {
        fprintf(stderr, "usage: %s --check | --apply\n", argv[0]);
        return 2;
    }
    apply = !strcmp(argv[1], "--apply");
    if (!has_expected_map())
        return fail("expected eth0 with EMAC 0, mode 7, switch port 4");
    if (access("/sys/module/netdriver", F_OK) || access("/sys/module/switch", F_OK))
        return fail("netdriver and switch must be loaded and sysfs mounted");
    if (!if_nametoindex("sw"))
        return fail("base interface sw is missing");
    if (lstat(ETHDRIVER, &st) || !is_ethdriver(&st))
        return fail("/dev/ethdriver is not the expected character device (83:0)");
    if (if_nametoindex("eth0")) {
        puts("eth0 already exists; nothing changed");
        return 0;
    }
    if (!apply) {
        puts("ready: eth0 -> switch port 4; no changes made");
        return 0;
    }
    if (geteuid() != 0)
        return fail("--apply requires the authorized root console");
    fd = open(ETHDRIVER, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        perror(ETHDRIVER);
        return 1;
    }
    if (fstat(fd, &st) || !is_ethdriver(&st)) {
        close(fd);
        return fail("opened device did not match /dev/ethdriver (83:0)");
    }
    if (ioctl(fd, SET_DEV_INFO, &dev) != 0) {
        perror("SET_DEV_INFO");
        close(fd);
        return 1;
    }
    if (ioctl(fd, ADD_DEV, &add) != 0) {
        perror("ADD_DEV");
        close(fd);
        return 1;
    }
    close(fd);
    if (!if_nametoindex("eth0"))
        return fail("driver returned success but eth0 did not appear; inspect dmesg");
    puts("eth0 registered (switch port 4); IP and link state unchanged");
    return 0;
}
