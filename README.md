# 中兴光猫 Flash 拆包

输入：`flash_full.bin`，256 MiB NAND 主区镜像。脚本只读输入，不向设备写入，也不运行固件里的程序。

```sh
# Python 3；安装 dtc 和 openssl 可生成 DTS 和解码后的配置 XML。
python3 extract_flash.py flash_full.bin extracted-new
```

`extracted/` 是本次结果。重跑请选择尚不存在的输出目录，预留约 1.3 GiB。输出包含设备配置，可能含设备标识和凭据，不宜原样分享。

**网络处理器（NP）**：微码逆向、查表引擎、快转。工具包和快速上手见 [npu/README.md](npu/README.md)（上板前先读 [npu/SAFETY.md](npu/SAFETY.md)），参考手册见 [NPU_HANDBOOK.md](NPU_HANDBOOK.md)。

调试 initramfs 的构建和免刷试用见 [DEBUG_ROOTFS.md](DEBUG_ROOTFS.md)。普通单 FIT 升级格式、候选 OTA 和验证边界见 [OTA_ZX279133.md](OTA_ZX279133.md)。替换 BusyBox、跳过原厂启动流程的串口版见 [SERIAL_BUSYBOX.md](SERIAL_BUSYBOX.md)；恢复原厂系统、只保留新 BusyBox 和 root 密码的版本见 [STOCK_BUSYBOX.md](STOCK_BUSYBOX.md)。在串口 Shell 里刷包和切换 bank 用 [ZX_FWSLOT.md](ZX_FWSLOT.md) 的 `zx-fwslot`。串口版里一键拉起 LAN1 网络和 SSH/scp/SFTP 见 [LAN_SSH.md](LAN_SSH.md)。NP 微码格式和自定义加速的可行性见 [NPU_MCODE.md](NPU_MCODE.md)。

## 物理分区

`extracted/mtd_dtb/` 按两套固件的 `fdt@133` 中一致的 `/part@256` 切片，并用镜像内容验证：两个银行头、FIT 和 JFFS2 都落在对应分区。`extracted/mtd_user_order/` 则严格按初始表的偏移切片，仅供对照；`/proc/mtd` 的列表本身不提供物理偏移，不能按列出顺序累加推定。两套切片各自都已逐项与原始镜像比较，完整覆盖 256 MiB；目录里的 `manifest.json` 包含偏移、大小、SHA-256 和全 `0xff` 标记。

| 分区 | 实际偏移 | 大小 (MiB) | 拆包结果 |
|---|---:|---:|---|
| boot | `0x0000000` | 2 | firstboot、U-Boot、FIT 设备树、环境变量 |
| kernel0 | `0x0200000` | 32 | FIT、ARM64 kernel、initramfs/rootfs；另有残缺 JFFS2 尾段 |
| kernel1 | `0x2200000` | 32 | FIT、ARM64 kernel、initramfs/rootfs |
| others | `0x4200000` | 6 | boot-state 文本/JSON、`ZXICVID` 板号，其余为擦除填充 |
| parameter tags | `0x4800000` | 4 | JFFS2、TAGH0201 JSON、光模块配置备份 |
| usercfg | `0x4c00000` | 8 | JFFS2、两份解码 XML |
| middleware | `0x5400000` | 4 | JFFS2、TAGH0201 JSON、一份解码 XML |
| wlan | `0x5800000` | 4 | 全 `0xff` |
| phoneapp0 | `0x5c00000` | 2 | JFFS2、完整 ARM32 `phoneapp` 和版本 |
| phoneapp1 | `0x5e00000` | 2 | 全 `0xff` |
| osgi0 | `0x6000000` | 45 | JFFS2、JRE、Felix 和 JAR |
| osgi1 | `0x8d00000` | 45 | 全 `0xff` |
| plugin_data | `0xba00000` | 69 | JFFS2、Felix 缓存和日志 |
| GN25L95_datas | `0xff00000` | 1 | JFFS2、`GN28L95_datas/UX3361.ini` |

## 从哪里看

- `extracted/boot/`：`firstboot.bin` 保留首个擦除块；`firstboot.elf`、`uboot-code.elf` 是便于反汇编的 AArch64 ELF 封装，不是原厂 ELF。`uboot.bin` 保留代码和 gzip FIT。另有 `uboot-trailer.bin`、`uboot-env.txt` 和 `dtb/*.dts`。环境变量文本可读，但首字段未通过按其余完整环境块计算的标准 CRC32；没有断定厂商算法或数据有效性。
- `extracted/kernel{0,1}/`：两套 FIT 的厂商头长度及 CRC32 都通过校验。`kernel.Image` 是解压后的 Linux 4.19.136 ARM64 Image，另附按 FIT 加载地址封装的 `kernel.elf`。`rootfs.cpio` 为无损解压的归档，`rootfs/` 为文件树（分别 2163、2158 条记录）。原始权限、设备结点等在 `rootfs_entries.json`；未在宿主机创建设备结点。两套 `decoded_etc/` 各解码 33 份配置：两边的 `db_default_Hebei_cfg.xml` 都通过了内部压缩 CRC，但原文本在第 1725 行标签不匹配，按原样保留。
- `extracted/auxiliary/<分区>/files/`：JFFS2 的当前文件树，`entries.json` 记录元数据，`status.json` 记录修复与截断情况。`filesystem.jffs2` 保留原始切片；4 个 CRC 异常块均从同一文件系统里对应 inode/文件偏移、匹配原 CRC 的副本恢复，仅写入 `filesystem.repaired.jffs2`。共验证了 67 个 JAR 的成员 CRC。
- `extracted/auxiliary/{usercfg,middleware}/decoded_config/`：3 份配置均已解码为可解析的 XML；原容器仍在 `files/`。解码报告附带 SHA-256，厂商签名尾部未验证。
- `extracted/auxiliary/bank0_appended_jffs2/`：`0x1a3d150` 起的 JFFS2 尾段含一个截断结点。只导出完整结点：`phapp_ver` 和 `phoneapp` 的前 4096 字节。版本和前缀与 `phoneapp0` 一致；完整程序应从 `phoneapp0/files/phoneapp` 读取。

拆包方法参考了通过 SSH 读取的 Mac 上 `~/code/ZXSLC_SR1010`（`3bdde9f`）里的 `README.md`、`scripts/extract_all.py`、`scripts/bootloader_to_elf.py` 和参数标签脚本。那份镜像的固定偏移、AES 固件容器和独立 JFFS2 rootfs 不适用于本镜像。本镜像的两套内核 FIT 不需要解密，rootfs 是 FIT 内的 LZMA initramfs。
