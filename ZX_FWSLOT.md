# zx-fwslot：串口 Shell 可用的升级器

串口版里没有 `pc`、`cspd`，原厂 `fw_flashing` 的运行环境不完整。`zx-fwslot` 照原厂升级器在**非安全板**上写普通单 FIT 包的流程重写，独立运行，只依赖 `/proc/mtd`、`/proc/cmdline` 和 `/dev/mtdN`。`/proc/zxic/versionstates`（`bspdriver.ko`）若存在，会用来交叉核对。

- 源码：`zx_fwslot.c`。MTD 读写和测试方法参考 SR1010 的 zte-fwslot，包格式和选 bank 规则按 ZX279133 重写。
- 成品：`build/zx-fwslot/zx-fwslot`，静态 ARM32 EABI5 soft-float。
- 串口粘贴上传脚本：`build/zx-fwslot/zx-fwslot-upload.txt`。
- 自带该工具的串口版：`build/serial-lan-ssh/serial-lan-ssh-ota-candidate.bin`，工具位于 `/debug/bin/zx-fwslot`。

## 命令

| 命令 | 作用 |
|---|---|
| `info` | 显示运行中的 bank、`BootImageNum`、两个 bank 能否被 U-Boot 启动及版本，以及 `others` 记录 |
| `check FILE` | 只校验包，不碰 Flash |
| `flash -n FILE` | 演练：完成全部校验并打印计划，不写 Flash |
| `flash FILE` | 写入**非运行** bank，回读校验后选中它 |
| `select 0\|1` | 按 U-Boot 的规则校验该 bank，然后设置为下次启动 |
| `switch` | 等于 `select <非运行 bank>`，不写 bank |

运行中的 bank 永远不会被擦写。以下情况会在第一次擦除之前拒绝执行：检测到 `cspd`、`fw_flashing`、`gpon_omci`、`pc` 进程；cmdline 与 versionstates 不一致；分区名、大小或偏移不符；`others` 里有无法识别的字节，或者在 0x1000 之后有会被擦掉的数据。

## 逆向得到的规则（V32.AA1.04）

- **U-Boot（zxboot）**：从 `others` 开头 0x1000 字节找 `BootImageNum=`，取 10 个字符按十六进制解析，非 0/1 时用 0。然后在 `kernel<N>` 中逐块找包头魔数，校验 `CRC32(hdr[0x14:0x110]) == hdr[0x110]`，读出 `0x1e0 + hdr[0x58]` 字节，校验 FIT 的 CRC 是否等于 `hdr[0x60]`。任一步失败就打印 "switch to kernel%d"，**只尝试另一个 bank 一次**。U-Boot 不读 `ImageNStatus`，也没有启动计数；内核起来以后跑崩，不会触发回退。
- **内核**：`bspdriver.ko` 从 cmdline 里的 `U-Boot <版本> <时间> <基址> <current> <状态1> <状态2>` 解析出 `/proc/zxic/versionstates`，这个文件只读。状态字节含义：bit0 Latest、bit1 Integrality、bit2 CRC、bit4 Syn/Upg。
- **fw_flashing（普通主包，非安全路径）**：
  1. `current` 取自 versionstates，目标 bank = 另一个；`/dev/mtd3` 对应 `0x200000`，`/dev/mtd6` 对应 `0x2200000`。包头 `0x70/0x74`、`0x80/0x84` 是两个 bank 的偏移和大小。
  2. 擦除整个目标 bank，再把包的 `[0, 0x1e0+FIT)` 写到 bank 偏移 0，最后回读比对。
  3. 坏块处理：坏块跳过；写失败用 `MEMSETBADBLOCK` 标坏后换下一块。
  4. `WritePrivateProfileInt`：读 `/dev/mtd7`（others）开头 0x1000 字节，对 `键=0x%08x,` 原位替换，不存在则追加到最后一个非 `0xff` 字节之后；然后擦除 0..0x80000 并写回 0x1000 字节。先写 `Image<目标>Status=0xffffffff`，再写 `BootImageNum=<目标>`。

`zx-fwslot flash` 按同样的顺序执行，两个键合并成一次擦写。`select`/`switch` 只修改 `BootImageNum`。

## 板上用法

1. 把 `zx-fwslot-upload.txt` 按行间隔粘贴到串口 Shell，会解到 `/tmp/zx-fwslot.XXXXXX/zx-fwslot` 并校验 SHA-256。
2. 先运行 `"$zx_fwslot_path" info`，确认 `running bank: 1`，并确认 bank 0 是原厂 `build="ZDFW2412095d005"`。
3. **回原厂**：`"$zx_fwslot_path" switch`，然后 `reboot`。这一步不写 bank，只改 `BootImageNum`。
4. **换成其他包**：先把包传到 `/tmp`，运行 `flash -n` 演练，再运行 `flash`，然后 `reboot`。

注意：bank 0 里的原厂 kernel0（`ZDFW2412095d005`，2024-12）比 kernel1 底包（`ZDFW2409067229c`，2024-09）新，而且带一个附加的 phoneapp 组件，本工具不会生成这种包。所以在串口版里对 stock-busybox 包执行 `flash`，会用较旧的 kernel1 系统覆盖它。想保留 kernel0，推荐的顺序是：先 `switch` 回 bank 0 的原厂系统，再在原厂系统里用 `fw_flashing -f` 把 stock-busybox 包刷进 bank 1。如果一定要覆盖 bank 0，先用 `nanddump` 备份并传出设备。

## 验证与边界

- `python3 -m unittest -v test_zx_fwslot`：共 14 项。宿主机编译的同一份源码，通过 `tests/fakemtd_zx.c` 在用真实 dump 初始化的假 NAND 上运行。垫片只允许写已擦除页、要求按页对齐，并记录每次擦写。覆盖了坏块（包括 bank 和 others 的第 0 块）、写失败、擦除失败、损坏 bank、厂商进程存在、状态不一致、分区不符等情况。每次写入后，都用一份独立的 Python 版 zxboot 选 bank 模型核对结果。
- `build_zx_fwslot.sh`：Bootlin 工具链需要 x86-64 glibc 主机，脚本注释里写了在 Debian 容器中运行的命令。
- **没有上板执行过**。只支持非安全启动路径：串口版未签名却能启动，说明这块板走的是非安全路径。安全板上 U-Boot 会验签，本工具不处理签名。只支持普通单 FIT 包，不写 phoneapp、OSGi 等附加组件。
- `Image<N>Status` 的语义只确认了 `gpon_omci` 会用到（OMCI 软件镜像管理），这里只是照原厂写法写入。
