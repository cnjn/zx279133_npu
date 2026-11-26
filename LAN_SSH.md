# 串口版：LAN1 + SSH/scp/SFTP 一键拉起

成品：[serial-lan-ssh-ota-candidate.bin](build/serial-lan-ssh/serial-lan-ssh-ota-candidate.bin)，26,331,328 字节，SHA-256 `d46980df4aed045e77b7c7d2fb541df3de98e1569359f0605ddf1cebc27a5fe6`。[离线校验报告](build/serial-lan-ssh/ota-report.json)含两级 CRC32。它在[串口版](SERIAL_BUSYBOX.md)的基础上，在 `/debug/` 下增加了下表的内容，同时带着 [`zx-fwslot`](ZX_FWSLOT.md)。启动流程和 inittab 都没有改，**开机后什么都不会自动运行**，需要时在串口里手动执行 `lan1-up`。

| 路径 | 内容 |
|---|---|
| `/debug/bin/lan1-up` | 一键脚本：驱动 → eth0 → 地址 → SSH |
| `/debug/bin/lab-modules` | 最小驱动集，从 `S43BSPDriver`、`S99modules` 精简而来 |
| `/debug/bin/lab-sshd` | 启动 Dropbear，只绑定一个 LAN 地址 |
| `/debug/bin/lan1-register` | 来自 `lan1_register.c`，把 eth0 注册到交换机端口 4 |
| `/debug/bin/dropbearmulti` | Dropbear 2026.94；`dropbear`、`dropbearkey`、`scp`、`dbclient` 都是指向它的链接 |
| `/debug/libexec/sftp-server` | OpenSSH 10.6p2 的 sftp-server |

二进制全部是静态 ARM32 EABI5 soft-float，和原厂用户态一致。

## 用法

```sh
lan1-up                    # 默认 192.168.1.1/24，SSH 监听 192.168.1.1:22
lan1-up 10.0.0.1/24        # 换一个地址
```

PC 接 LAN1 口，配置同网段地址后：

```sh
ssh root@192.168.1.1                      # 密码 root
scp file root@192.168.1.1:/tmp/           # OpenSSH 9+ 默认走 SFTP，由 sftp-server 处理
scp -O file root@192.168.1.1:/tmp/        # 旧 scp 协议，由 dropbear 的 scp 处理
```

- **主机密钥**：在 tmpfs `/var/tmp/dropbear/` 里生成，每次重启都会变。PC 端可用 `ssh-keygen -R 192.168.1.1` 清掉旧记录，或者加 `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`。镜像里不放私钥。
- **只用公钥登录**：把公钥写进 `/root/.ssh/authorized_keys`，然后 `kill $(cat /var/tmp/dropbear/dropbear.pid); lab-sshd`。只要这个文件存在，就会加 `-s` 禁止密码登录。原厂 `/root` 是 0775、属主 uid 1000，dropbear 会因此拒绝其中的公钥，所以 `lab-sshd` 会在内存里把它改成 `root:root 0700`。
- **日志**：`/var/tmp/dropbear/dropbear.log`。
- **重复执行**：已加载的模块、已有的 eth0 和地址、正在运行的 dropbear 都会跳过；交换机端口 4 每次都会重新开关一次。

## 驱动集（`lab-modules`）

加载顺序：`bspdriver` → 外置 PHY → `np_133` → `zx_ponreg_133` → `qos_mod` → `region_init` → `wan_bridge` →（有 `peripheral.ko` 时加载它）→ `iprt` → `ffe` → `netdriver` → `ifconfig sw up` → `multicast` → `switch` → `ip link set idm0/idm1 up` → 关闭送 CPU 限速。

- **送 CPU 限速**：`switch.ko` 初始化时把交换机送往 CPU 的流量限制在 4000 pps，局域网上传到光猫因此只有约 2 MB/s（下载不受影响，约 80 MB/s）。`lab-modules` 会执行 `echo enable=0 > /proc/pon/switch_debug/sw_set_trap_to_cpu_queues_rate_limit` 关闭它，实测纯 TCP 上传升到 60 MB/s。代价是 CPU 不再受包风暴保护，只适合实验网络；设置 `LAB_CPU_RATELIMIT=1` 可以保留限速。
- **scp 速度**：关闭限速后，scp 上传、下载都在 12 MB/s 左右，这是 dropbear 在这颗 CPU 上用 chacha20-poly1305（OpenSSH 默认算法）的加解密上限。aes128-ctr 更慢，约 5 MB/s：这颗 A53 没有 ARMv8 AES 扩展，而且程序按 ARMv5 编译。大文件可以改用 `nc` 走明文 TCP，约 60 MB/s。

- **idm0/idm1 必须拉起**：它们是 NP 把包送给 CPU 的接收通道（`np_133` 的 "idm net"）。S99modules 是在 DSP 驱动旁边把它们拉起来的；早期版本精简时把这一步一起删掉了，结果交换机端口 4 的 MIB 能看到收包，eth0 的 RX 却一直是 0，ARP 解析不出来。板上已确认：拉起这两个接口后就能 ping 通。

- 外置 PHY 先看 `/proc/pon/outer_phy` 里 `xmac0` 的值，读不到时用 `rlt8226b`（这块板以前手动拉起时用的就是它）。可以用 `LAB_PHY=名字` 指定，或 `LAB_PHY=none` 跳过。原厂把 PHY 驱动放在 `np_133` 之前加载，此处沿用；以前手动操作时是在最后才加载 `rlt8226b`，两种顺序都还没有在板上对比过。
- 名字带 pon 的 `zx_ponreg_133` 不能去掉：`switch.ko` 的 `depends=` 里有它。
- 去掉的部分：`/proc/pon/upmode` 分支里的 GPON/XG-PON/EPON MAC 驱动、`pon`/`olt`/`omci`/`oam` 接口、`optical.ko`、GN28L9x 驱动和 `bobtest`（**它会改写光模块的激光校准参数**）、DSP/语音、RTSP ALG、`sismac`、download/upload、xHCI、TUN、老化测试和 `excp_reborn.sh`。
- `qos_mod`、`region_init`、`wan_bridge`、`iprt` 和 netdriver 之间没有符号依赖，只是照原厂顺序保留下来。能不能再精简，需要上板逐个试。

`lan1-up` 后面的步骤和以前手动操作的一样：`lan1-register --apply`、`ip link set eth0 up`、`siswitch -spen 4 0/1`（每步间隔 3 秒）、`ip addr add`。

## 构建

```sh
# 1. Dropbear + sftp-server（Bootlin 工具链需要 x86-64 glibc + make，在容器里运行）
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/w" -w /w \
  sr1010-mesh-shim-builder-x86:cross sh build_ssh.sh        # 输出到 build/lan-ssh/
# 2. 串口版 initramfs + OTA 候选
python3 serial_rootfs.py extracted/kernel1 build/busybox/busybox-arm build/serial-lan-ssh \
  --tool zx-fwslot=build/zx-fwslot/zx-fwslot --lan-ssh build/lan-ssh
python3 build_ota.py build --serial-shell extracted/mtd_dtb/kernel1.bin \
  build/serial-lan-ssh/debug-offline-test.itb build/serial-lan-ssh/serial-lan-ssh-ota-candidate.bin
python3 build_ota.py inspect build/serial-lan-ssh/serial-lan-ssh-ota-candidate.bin
```

- 源码包：`dropbear-2026.94.tar.bz2` 的 SHA-256 与上游 `SHA256SUM.asc` 一致；`openssh-10.6p2.tar.gz` 通过了 OpenSSH 发布密钥（`7168 B983 815A 5EEF 59A4 ADFD 2A3F 414E 7360 60BA`）的 GPG 验签。两份哈希记录在各自目录的 `*.sha256` 里，`build_ssh.sh` 每次构建前都会核对，并从压缩包重新解压，不使用已经解开的目录。
- Dropbear 的编译选项在 `ssh_localoptions.h`：会话 PATH 以 `/debug/bin` 开头，这样 `scp -t` 才能找到；`SFTPSERVER_PATH=/debug/libexec/sftp-server`；关闭 DSS、X11 转发和 MOTD；不编进 zlib、PAM、utmp/wtmp/lastlog。sftp-server 用 `--without-openssl --without-zlib` 构建。
- `debug_overlay/README.txt` 和 `serial-shell` 没有改，所以已有的串口版产物仍然能通过 `verify_serial` 的逐字节核对。

## 验证与边界

- `python3 -m unittest -v test_serial_rootfs test_build_ota test_debug_rootfs`：新增的 `test_lan_ssh_bundle` 检查内容、链接、inode 唯一性，以及改动后的脚本、hard-float 二进制和缺件都会被拒绝。`test_compiled_binary` 用真实的 ARM BusyBox 对三个脚本做 `ash -n` 语法检查。
- `sh tests/ssh_qemu_smoke.sh`：在 qemu-arm 用户态下跑 ARM 版 dropbear，主机的 OpenSSH 客户端依次验证公钥登录、SHA-512 密码登录、`scp`（SFTP 模式）、`scp -O` 的上传和下载，以及 `sftp`。`/debug` 路径由测试里的主机端包装脚本映射到临时目录，在板上它们是真实路径。
- **板上验证**：在内存里替换 `lab-modules` 后，从干净启动开始执行 `lan1-up`，Mac 能 ping 通 192.168.1.1（约 0.5 ms）。本 OTA 包本身还没有刷写验证。
- 不要执行 `siswitch -gdaen`：厂商 `switch.ko` 的 `sw_port_get_port_da_find_en` 会触发栈保护 panic，导致整机重启。如果内核随机数池还没初始化，第一次生成主机密钥可能要等一会儿，`lab-sshd` 会打印当前的 `entropy_avail`。
- SSH 只监听指定的 LAN 地址，但 root 默认可以用实验室密码登录：这个口只能接在可信的实验网络上。
