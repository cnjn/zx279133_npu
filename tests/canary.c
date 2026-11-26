/* Lab probe: log every new process (pid ppid uid cmdline) seen in /proc every
 * 50 ms, and the sender of any catchable termination signal, to a log file. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int logfd = -1;
static unsigned char seen[65536 / 8];

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void describe(int pid, char *out, size_t len)
{
    char path[64], buf[512];
    int fd, n, ppid = -1, uid = -1;
    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : 0;
    if (fd >= 0) close(fd);
    if (n < 0) n = 0;
    for (int i = 0; i < n; i++) if (!buf[i]) buf[i] = ' ';
    buf[n] = 0;
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof line, f)) {
            if (!strncmp(line, "PPid:", 5)) ppid = atoi(line + 5);
            else if (!strncmp(line, "Uid:", 4)) uid = atoi(line + 4);
            else if (!n && !strncmp(line, "Name:", 5)) {
                snprintf(buf, sizeof buf, "[%s]", line + 6);
                buf[strcspn(buf, "\n")] = 0;
            }
        }
        fclose(f);
    }
    snprintf(out, len, "pid=%d ppid=%d uid=%d %s", pid, ppid, uid, buf);
}

static void logline(const char *s)
{
    char line[700];
    int n = snprintf(line, sizeof line, "%.2f %s\n", now(), s);
    if (logfd >= 0) write(logfd, line, n);
}

static void on_signal(int sig, siginfo_t *si, void *ctx)
{
    char who[600], msg[700];
    (void)ctx;
    describe(si->si_pid, who, sizeof who);
    snprintf(msg, sizeof msg, "SIGNAL %d code=%d from %s", sig, si->si_code, who);
    logline(msg);
    /* also the sender's parent */
    char path[64], line[128];
    snprintf(path, sizeof path, "/proc/%d/status", si->si_pid);
    FILE *f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, "PPid:", 5)) {
                describe(atoi(line + 5), who, sizeof who);
                snprintf(msg, sizeof msg, "  sender parent %s", who);
                logline(msg);
            }
        fclose(f);
    }
}

int main(int argc, char **argv)
{
    struct sigaction sa = { .sa_sigaction = on_signal, .sa_flags = SA_SIGINFO | SA_RESTART };
    int sigs[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT, SIGUSR1, SIGUSR2, SIGPIPE, SIGALRM };
    logfd = open(argc > 1 ? argv[1] : "/tmp/canary.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd < 0) return 1;
    sigfillset(&sa.sa_mask);
    for (unsigned i = 0; i < sizeof sigs / sizeof *sigs; i++) sigaction(sigs[i], &sa, NULL);
    if (fork() > 0) return 0;  /* detach */
    setsid();
    logline("canary start");
    for (;;) {
        DIR *d = opendir("/proc");
        struct dirent *e;
        while (d && (e = readdir(d))) {
            int pid = atoi(e->d_name);
            if (pid <= 0 || pid >= 65536 || (seen[pid / 8] & (1 << (pid % 8)))) continue;
            seen[pid / 8] |= 1 << (pid % 8);
            char who[600];
            describe(pid, who, sizeof who);
            logline(who);
        }
        if (d) closedir(d);
        usleep(50000);
    }
}
