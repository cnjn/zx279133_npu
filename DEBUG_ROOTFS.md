# ZX279133 调试 rootfs（第一阶段）

这版只增加 `/debug/`，不改 `/init`、`inittab`、启动脚本、账号、网络服务、厂商模块或微码。不启用额外的调试监听端口。以原始 `newc` 归档为底，在 trailer 前追加记录，原厂的文件、权限、属主、硬链接和设备结点记录逐字节保留；不用宿主机解包后的目录倒推归档元数据。

## 构建

```sh
# 输出目录必须不存在；任选对应的原厂 bank 作为底包，不混用二者的文件。
python3 build_debug_rootfs.py extracted/kernel0 build/debug-kernel0
# 另一套原厂版本：
python3 build_debug_rootfs.py extracted/kernel1 build/debug-kernel1
```

`build/debug-kernel0/` 已离线生成。产物：

| 文件 | 用途 |
|---|---|
| `debug-tools.tar.gz` | 仅含 `/debug` 的相对路径归档，可先在现有系统的 `/tmp` 试用 |
| `debug-rootfs.cpio` | 保留原厂记录的 `newc` initramfs |
| `debug-initramfs.lzma` | LZMA-Alone 压缩的 initramfs |
| `debug-offline-test.itb` | 只替换 `/images/initramfs@133` 的 `data` 属性的 FIT，用于离线检查；**不是可上传升级包** |
| `manifest.json` | 输入 FIT 的哈希、产物哈希和尺寸、追加路径 |

可通过 `--tool NAME=PATH`（可重复）引入可信的静态 Linux 工具，例如 `--tool strace=/path/to/arm-strace --tool gdbserver=/path/to/arm-gdbserver`。默认产物不含这两个第三方二进制。厂商内核是 AArch64 4.19.136，原厂 BusyBox 等用户态程序则是 32 位 ARM EABI5 soft-float（`/lib/ld-linux.so.3`）。脚本只接收没有 ELF 解释器及共享库依赖的 ARM EABI5/AArch64 可执行文件；这不是运行兼容性证明，仍要核对目标 CPU 指令集和 Linux 4.19 所需的系统调用。用 `strace`/`gdbserver` 时也要核对目标进程的架构。

## 不刷机，先试工具

在已经有权限的 shell 上，把 `debug-tools.tar.gz` 通过现有传输方式放到 `/tmp/`（原厂 `fstab` 将 `/tmp` 挂为 tmpfs）。不需要开放新端口：

```sh
umask 077
work=$(/bin/busybox mktemp -d /tmp/ont-debug.XXXXXX) &&
  /bin/busybox tar -oxzf /tmp/debug-tools.tar.gz -C "$work" &&
  /bin/sh "$work/debug/bin/ont-info" summary
```

其余子命令是 `npu`、`net`、`crypto` 和 `kconfig`。工具只读本机信息，不自动挂 debugfs，不更改运行配置。`npu` 会检查 `np_133`、近期微码日志、还存在时的 `mcode_133.bin` 哈希；文件在启动后不在不等于加载失败。两套原文件的 SHA-256 都为 `d9069f9d6224b84ac37b6b9a4f63c1571062daa6a3da2ae8c3ee59961afe6c9c`。`crypto` 输出已注册的相关算法和 TUN 结点是否存在，不能证明某个协议实际上走了硬件路径。两个原厂 `kernel.Image` 都没发现常见的内嵌 IKCONFIG 标记；若 `/proc/config.gz` 不存在，不要把 `kconfig` 无法读取误判为某个选项未启用。

## 原厂升级链路

普通单 FIT 的升级布局已通过 `cspd`、`fw_flashing` 反汇编与 `kernel1` bank 内容交叉验证，并另生成了 [`build/debug-kernel1/debug-ota-candidate.bin`](build/debug-kernel1/debug-ota-candidate.bin)。见 [OTA_ZX279133.md](OTA_ZX279133.md) 的格式、重建步骤和签名限制。对目标机的安全状态、上传和启动还没有实测；仍不要上传裸 `debug-offline-test.itb`。

## 已做的离线验证

`python3 -m unittest -v test_debug_rootfs` 的 6 项测试通过。两套真实 bank 都构建通过，原始 CPIO 的 2163 / 2158 条记录逐字节不变。`kernel0` 成品 FIT 为 25,932,735 字节；`dtc` 能读取，保留 40 个启动配置，LZMA 解压与输出 CPIO 完全一致。用 QEMU user mode 的原厂 ARM BusyBox 检查了语法和 `--help`。这些不是板上启动或升级测试。

## 后续 WireGuard

先用原厂微码测纯软件 WireGuard 基线，再区分 CPU 花在 ChaCha20-Poly1305、UDP 收发还是转发上。现有 AES/SM4 硬件不能替代 WireGuard 的 ChaCha20-Poly1305。即使密码引擎不支持它，NPU 的收发/分类/转发卸载仍可能有收益；不要把 `/proc/crypto` 有某项注册与 WireGuard 实际命中混为一谈。
