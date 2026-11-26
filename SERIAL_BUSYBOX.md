# ZX279133 串口 Shell 调试版

成品已删除：最早的串口版（无附加工具）和 serial-busybox-fwslot 已从 `build/` 移除，现在使用 [serial-lan-ssh](LAN_SSH.md)（串口 Shell + LAN1/SSH + `zx-fwslot`）。本文保留串口 Shell 的通用说明；编译好的 BusyBox 在 `build/busybox/`。

## 启动及使用

- 原厂 DTB 指定 `rdinit=/sbin/init` 和 `console=ttyAMA0,115200n8`。`/sbin/init` 原样链接到 `/bin/busybox`；若走 `/init`，原厂脚本同样调用新 BusyBox 的 `init`。PID 1 读取新的 `/etc/inittab`，只挂 `proc`、`sysfs` 和 `/var/tmp` 的 tmpfs，然后在 `ttyAMA0` 启动交互式 ash。串口参数为 **115200 8N1**。键入 `exit` 后 PID 1 会重开 Shell。
- UART 直接进入 root shell，不弹出密码提示。`/etc/shadow` 里的 root 密码已设为 `root`（SHA-512 crypt）；其他账号行不变。新 BusyBox 不设 setuid，只适用于物理隔离的实验设备；不要用此密码在网络上开启登录服务。
- 不执行 `/etc/init*` 下的原厂启动脚本，也不启动 Telnet、SSH、Web、DHCP 等服务。原厂脚本、PON/NPU 模块和微码仍在镜像里，但不会自动加载，因此**不提供正常光猫联网功能**。
- `/bin/busybox` 是真正替换的静态 **BusyBox 1.38.0**，ARM32 EABI5 soft-float，含 408 个 applet，见 [清单](build/busybox/busybox-applets.txt)。`tree`、`lsblk`、`vmstat` 等新增命令可直接用；所有 applet 都可用 `busybox <命令>` 调用。原厂启用了 `nuke`（强制递归删除，近似 `rm -rf`）；上游 1.38.0 也有这个 applet，但默认关闭，本构建保留了 `# CONFIG_NUKE is not set`。


这是离线重打包后的普通 OTA 候选，**不是厂商签名包，未上传、未刷写、未启动**。真机前先确认安全策略、活动 bank 和 UART 回退路径；进 Shell 后没有原厂 Web 升级服务，不能指望用 Web 页面刷回。参见 [OTA_ZX279133.md](OTA_ZX279133.md)。

## 构建与验证

BusyBox 使用上游 `busybox-1.38.0.tar.bz2` 和 Bootlin `armv5-eabi--musl--stable-2024.05-1.tar.xz`（Linux 4.19 头文件），两者下载后通过其发布方提供的 SHA-256 校验。本机在已有 Debian 构建容器中交叉编译，没有安装系统包。`build_busybox.sh` 使用 `defconfig` 加静态链接、SHA-512 默认密码算法等设置；配置存于 [`busybox.config`](build/busybox/busybox.config)。

```sh
# 已有编译好的静态 ARM BusyBox；从对应 kernel1 底包重建。
python3 serial_rootfs.py extracted/kernel1 build/busybox/busybox-arm build/serial-rebuild
python3 build_ota.py build --serial-shell extracted/mtd_dtb/kernel1.bin \
  build/serial-rebuild/debug-offline-test.itb build/serial-rebuild/serial-busybox-ota-candidate.bin
python3 build_ota.py inspect build/serial-rebuild/serial-busybox-ota-candidate.bin
python3 -m unittest -v test_serial_rootfs test_build_ota test_debug_rootfs
```

验证了新 BusyBox 的 ARM 用户态执行、Shell 脚本语法、密码哈希、FIT、LZMA 和两级 CRC32。原始 initramfs 只有 `/bin/busybox`、`/etc/inittab`、`/etc/passwd`（仅元数据）和 `/etc/shadow` 四条记录变化，其余 2154 条逐字节不变。QEMU 用户模式不等于板上启动验证。
