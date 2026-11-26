# ZX279133 原厂系统 + 新 BusyBox

**SSH/scp**：包里另有 `/debug`（Dropbear、`scp` 链接、sftp-server、`lab-sshd`）。原厂系统起来以后执行 `/debug/bin/ssh-up`：它取 `br0` 的 IPv4 地址（一般是 192.168.1.1），在 iptables 里放行 LAN 侧的 22 端口，再启动 dropbear。开机不会自动启动 SSH。厂商防火墙重建规则后，重新执行一次 `ssh-up` 即可。root 密码是 `root`，shadow 第 3 个字段写成 `1`：BusyBox `login` 会拒绝空值或 0。构建时加 `--ssh build/lan-ssh`。

成品：[stock-busybox-ota-candidate.bin](build/stock-busybox/stock-busybox-ota-candidate.bin)，26,347,056 字节，SHA-256 `56d4a75952c4d57950184e2e178cca400da578183e714f0ddf3ce52315fc4f6a`。[离线校验报告](build/stock-busybox/ota-report.json)含两级 CRC32。用于从[串口版](SERIAL_BUSYBOX.md)回到原厂系统，同时保留新 BusyBox 和实验室 root 密码。

## 与原厂 kernel1 的差别

initramfs 2159 条记录中只有两条内容不同，其余逐字节保留：

- `/bin/busybox`：与串口版相同的静态 BusyBox 1.38.0（SHA-256 `d8d30465…db10ea861`）。
- `/etc/shadow`：root 行换成串口版的 SHA-512 哈希（密码 `root`），其他账号行不变。

这两条记录的 inode、权限、属主和 mtime 都沿用原厂（原厂 `rcS` 启动时会 `chmod 600 /etc/shadow`）。`/etc/inittab`、`/etc/passwd`、启动脚本、模块和微码都是原厂原样，不追加 `/debug`，因此 `/debug/applets/tree` 这类快捷入口没有了，请改用 `busybox tree`。内核、DTB 和 OTA 头的版本与版型字段都来自 `kernel1`。

root 密码只影响 UART 上 `getty` → `login` 以及 `su`。原厂 `/sbin/telnetd` 是厂商程序，它通过 `pm_telnet_user_get` 从配置库取账号，不读 `/etc/shadow`。

## 兼容性检查

- applet：原厂 BusyBox 1.33.1 有 386 个，新版有 408 个，只缺 `nuke`（上游默认关闭）。在原厂普通文件里没有找到调用 `nuke` 的脚本，`/bin/nuke` 这个链接会变成无效。
- 原厂脚本依赖的写法，例如 `sed 's/^upmode: /\1/'` 里空的 `\1`、ash 的 `[[ ]]` 和 `[ a == b ]`，在两版 BusyBox 下输出一致。`rcS`、`S99modules`、`S01userconfig` 都能通过新 ash 的 `-n` 语法检查。
- 原厂 `$5$`（SHA-256 crypt）哈希的计算结果在两版 BusyBox 和 OpenSSL 中一致。
- 原厂 BusyBox 是 glibc 动态链接，新版是 musl 静态链接，二者都不设 setuid。厂商程序若解析 `ps`、`ifconfig` 等命令的输出，格式差异需要上板观察。

以上检查都在 QEMU 用户态完成，**没有经过上板启动验证**。

## 重建

```sh
python3 stock_busybox_rootfs.py extracted/kernel1 build/busybox/busybox-arm build/stock-rebuild
python3 build_ota.py build --stock-busybox extracted/mtd_dtb/kernel1.bin \
  build/stock-rebuild/debug-offline-test.itb build/stock-rebuild/stock-busybox-ota-candidate.bin
python3 build_ota.py inspect build/stock-rebuild/stock-busybox-ota-candidate.bin
python3 -m unittest -v test_stock_busybox_rootfs test_serial_rootfs test_build_ota test_debug_rootfs
```

## 刷入

串口版里不要直接调用原厂 `fw_flashing`，改用 [zx-fwslot](ZX_FWSLOT.md)。bank 0 的原厂 kernel0 比本包的 kernel1 底包新，所以推荐的顺序是：先用 `zx-fwslot switch` 回到 bank 0 的原厂系统，再在原厂系统里用 `fw_flashing -f` 把本包刷进 bank 1。

| 内容 | 前 512 字节 SHA-256 |
|---|---|
| dump 时的 kernel0（原厂） | `ca481d5ed49df4e3` |
| dump 时的 kernel1（原厂） | `3e86b36fd8eda1a3` |
| 串口版 | `fe639355927dc20d` |
| 本包 | `3a4ea410cfab62d2` |

## 运行一分钟左右后所有进程被杀

现象：开机约 50–70 秒后，除 init 外的进程全部消失，只有串口 getty 被 init 重新拉起；内核不重启，Web、telnet 都没了。

根因是厂商 `osgid` 的 bug（板上用 `tests/canary.c` 记录进程和信号，并反汇编 `osgid`、`libcommfun.so` 确认）：

```c
pid = getMainPidByTaskName("java");   /* 没有 java 进程时返回 -1 */
snprintf(cmd, 32, "kill -9 %d", pid); /* 变成 "kill -9 -1" */
PcStartProgram("kill", cmd);          /* pc 以 root 直接 exec /bin/kill */
```

`osgid` 在 Java（OSGi/felix）还没启动时就走到"重启 OSGi 框架"的分支，`kill -9 -1` 把包括 `pc` 在内的所有进程杀掉，后续的重启也就不会发生。Java 本身能正常运行；这次开机里 `osgid` 没有启动它，具体是哪个前置条件没满足还没查清。

处理：本镜像给 `/bin/osgid` 打了一个字节的补丁（文件偏移 `0xa360`），把格式串 `kill -9 %d` 改为 `kill -9 %u`。真实 PID 的输出不变；-1 会变成 `4294967295`，只会返回"没有这个进程"。`pc` 不经过 `/bin/kill`，所以包装 `/bin/kill` 拦不住，已放弃这个做法。板上验证（内存中打补丁后重新拉起 `pc`）：150 秒内进程数稳定在 75 个左右，Java 在约 50 秒时启动，Web 返回 200。整个刷写包尚未在板上验证。

另外，原厂 `rcS` 会执行 `chmod 4755 /bin/busybox`。`build_busybox.sh` 已按原厂方式打开 `FEATURE_SUID`、`SUID_CONFIG`、`SUID_CONFIG_QUIET`，以 `csp` 等普通用户身份调用 applet 时会降回原有权限（实测之前是 `euid=0`）。这个问题不是全杀的原因，但同样需要修。
