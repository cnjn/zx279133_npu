# 上板安全须知

板子挂了不可怕：重启后表和微码都会回到原样。可怕的是不知道它为什么挂。下面每一条都是实际踩过的坑，括号里是出处（`NPU_MCODE.md` 的实验编号）。

## 1. 出事了怎么办

1. `npu/npu health`，看卡住的线程数、ping、送 CPU 的计数（`idm_dma_to_cpu`、`eth0_rx`）。
2. 如果 ping 不通，但 `idm_dma_to_cpu` 停住不涨，多半是全局配置表 #34 被清掉了（见第 2 节第 2 条），先查它：`npu/npu se read 34 0`。本机的原值是 `03272000 0 0 0`。写回原值不用重启：`npu/npu sh "echo 34 0 4 3272000 0 0 0 > /sys/devices/platform/np/se_debug/cpu_set_eram_by_table_width"`。
3. 微码改坏了：`npu/npu restore`。
4. 其他情况：`npu/npu reboot`。它会经串口重启板子，等到 shell 提示符后再跑 `lan1-up`。
   - 重启过程中**绝不要往串口打字**：任何按键都会让 U-Boot 停在 `=>`。如果真停住了，`board_reboot.py` 会自动输入 `run bootcmd` 继续启动。
   - `lan1-up` 不能接管道（`| tail` 之类会让它挂住）。
5. 板子自己崩溃重启过的迹象：`uptime` 很短，`/sys/devices/platform/np` 不存在（NP 驱动由 `lan1-up` 加载），Mac 上 ping 报 "Host is down"。这时用 `npu/npu reboot --lan-only`，它不再重启，只运行 `lan1-up`，十几秒就好。
6. 重启后，自建的表、快转规则、#50 表项全部消失，`npu fast list` 会自动忘掉旧规则。

## 2. 不要碰的驱动接口

| 接口 | 后果 | 出处 |
|---|---|---|
| `acl_debug/acl_*_table_get`（任意一张 ACL 表） | `get` 和 `show_one` 互相调用，无限递归，内核栈溢出后 panic 重启。用 `npu fast dump` 代替 | 实验 101 |
| `se_debug/cpu_get_eram_by_table_width` | **读完把表项清零**（驱动走 `…_with_free`，读模式 1）。读 #34 第 0 项后，送 CPU 的包进了错误的队列，LAN 管理就断了。用 `se_debug/eram_table_get SDT 索引` 或 `npu se read` 代替 | 实验 101 |
| 绕开 acl_debug 直接改 ACL 表（#111–#122）：`cpu_set_eram_by_table_width`、上面那个清零的读、自己的微码写表 | 驱动保存着每个表项的副本。之后再对**同一项**执行 `acl_*_set` 时，驱动发现副本和硬件不一致，就会走进同一个无限递归，内核崩溃重启。`npu se write` 默认拒绝写这些表。已经改过的话，重启后再用 acl_debug | 实验 101 |
| 查表操作码 19（`lkup` fam 低 5 位 = 0x13） | 执行一次，NP 到 CPU 的通路就断，恢复微码也没用，只能重启 | 实验 88 |
| 用错模式的计数查表（操作数 bit 28 = 0 的未知模式，例如 32 位表配 bit 28 = 0，128 位表配模式 0x10） | 计数引擎不再应答，之后所有要计数的包都卡住，只能重启 | 实验 99 |
| 对已存在的 SDT 再执行 `creat_hash_sdt` | 弄乱表定义 | 实验 83 |

## 3. 写微码时

- `mov` 的目的寄存器 ≥ r32（编码 ≥ 1024）实际上是跳转，写错会造成线程卡死。卡死的线程约 24 个时 NP 停转，只能重启（实验 79）。
- 写后读之间要隔一条指令（`nop`）；`npisa.hazards()` 和 `snippet.py` 会帮你检查。
- 整份加载的镜像，主程序长度要补到 4 字的倍数，因为加载器按 4 字一组写（`bench.py`、`npu load` 已经处理）。
- 挂钩只能挂在入口模板之后（PC 5047 可以；4992、4996 会丢包）。
- 没把握的新指令或新查表，先每次只发一个包，发完 `npu health` 或 ping 一下再继续。
- 断点（`ppu_debug/break_point_set`）只会拦包，拿不到寄存器快照（实验 15–17）。

## 4. 实验环境本身

- **不要把 Mac 自己的 MAC 写进 MAC 表 #50**：它的 ARP 广播会改走广播路径，被 "boardcast flood disable" 丢掉，Mac 就连不上板子了。测试一律用假源 MAC（`config.test.fake_sa`），`npu mac50` 会拒绝写 Mac 自己的 MAC。
- **串口一次只能一个进程用**：不要同时跑两个 `npu` 命令，也不要同时开串口终端。
- 串口 shell 会丢长命令行里的字符（约 200 字以上就不可靠）。`npu sh` 会拒绝超长命令；长命令用 `npu run`，它会先把脚本推到板上再执行。
- 推送失败会在板上留下 `nc -l` 进程，占住端口；`npu` 每次推送前会先 `killall nc`。
- 驱动打印级别：`npu run` 临时调成 3，结束后改回 1。不要让它一直停在 3，dmesg 会被刷满。
- `table_debug/debug_stat_show` 前几行打印到控制台，其余进 dmesg；`npu stats` 两边都读。

## 5. 数据

- `flash_full.bin` 和 `extracted/` 里有设备配置、凭证和设备标识，不要上传或分享。`.gitignore` 已经排除了它们。
- 调试 rootfs 的 root 密码是故意设的弱密码，只能在隔离的实验网络里用。
