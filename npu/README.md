# npukit：ZX279133 网络处理器（NP）工具包

用这个工具包可以读懂、修改光猫 NP 的微码，读写查表引擎（SE）的表，以及下发原版微码自带的快转规则（NAT44／NAT66、DS-Lite、PPPoE、VLAN）。

所有操作都通过一条命令 `npu/npu` 完成。**上板之前先读 [SAFETY.md](SAFETY.md)**：有几个驱动接口会让内核崩溃，或者悄悄清掉表项。

背景资料：

- [NPU_HANDBOOK.md](../NPU_HANDBOOK.md)：参考手册，按主题组织，日常查这个。
- [NPU_ZX133_MAP.md](../NPU_ZX133_MAP.md)：原版微码的功能块地图。
- [NPU_MCODE.md](../NPU_MCODE.md)：实验记录，每条结论的证据都在这里，按实验编号查。

## 1. 环境

一共三台机器：

```
分析机（跑 npu）──ssh──> 跳板 Mac ──USB 串口──> 光猫 UART
                            └──网线（LAN1）──> 光猫 LAN 口
```

- **分析机**：Linux，Python ≥ 3.11（要用 `tomllib`）。离线工具只需要这一台。`npu ko dis` 还需要一个 AArch64 的 objdump。
- **跳板 Mac**：分析机能免密 ssh 登录，装有 python3。
  - 用户要在 `access_bpf` 组里，`npu send` 发原始帧要用 BPF；装过 Wireshark 的 Mac 一般已经是。
  - 它的网卡接光猫 LAN1，IP 用 192.168.1.2。
- **光猫**：跑调试 rootfs（构建和试用见 [DEBUG_ROOTFS.md](../DEBUG_ROOTFS.md)）。串口 shell 的提示符是 `ont-shell:~ #`，`/debug/bin/lan1-up` 用来把 LAN1 拉起来。
- **固件文件**：原版微码和驱动从你自己机器的 Flash dump 里拆出来（仓库根目录 `README.md` 里的 `extract_flash.py`），放在 `extracted/` 下。这些文件不进 git：里面有设备配置和凭证。

## 2. 第一次使用

```sh
cp npu/config.example.toml npu/config.toml   # 填 Mac 地址、串口设备、网卡、两边的 MAC
npu/npu config                               # 检查配置，列出缺的项
npu/npu mac-sync                             # 把 npu/mac/ 下的脚本拷到 Mac
npu/npu selftest                             # 只跑离线测试
npu/npu selftest --board                     # 再检查 Mac、串口、NP 状态、LAN 推送
npu/npu selftest --fast                      # 再加一次快转冒烟测试（会下发并删除一条规则）
```

全部通过就说明环境正常。`--fast` 大约要半分钟（一次串口往返约 0.3 秒）。

## 3. 常用任务

### 读微码

```sh
npu/npu dis --names > /tmp/zx133.s           # 原版微码的带名字汇编（默认就是原版镜像）
npu/npu flow                                 # 从各入口出发能到达哪些出口
```

带注释的现成清单在 `build/npu-re/asm/mcode_133.named.s`。指令含义见手册第 4 章，功能块位置见 `NPU_ZX133_MAP.md`。

### 改一条指令，上板看效果，再恢复

```sh
npu/npu inst 3429                            # 读 PC 3429 所在的 4 个字
npu/npu inst 3429 0018000601000003           # 写回（十六进制 64 位字）
npu/npu restore                              # 整份恢复原版微码
```

### 写一段自己的微码挂进原版

```sh
npu/npu patch my.s 5047 3569 /tmp/out my     # 在 3569 起汇编 my.s，把 PC 5047 换成 call
npu/npu run -l 1 -f /tmp/out/my.apply        # 装上（生成的是 inst_set 命令，钩子最后写）
npu/npu run -l 1 -f /tmp/out/my.restore      # 卸下（钩子最先恢复）
```

完整示例（整个 UDP 反射器都在 NP 里跑）：`build/npu-exp/udp_reflector.s`，讲解见手册第 10 章。PC 3569–3625 是原版里没人用的死代码，可以放自己的代码；PC 5047 是入口模板之后第一个能安全挂钩的位置。另一种做法是改汇编后整份加载：先 `npu/npu asm SRC -o OUT.bin`，再 `npu/npu load OUT.bin`。

### 看计数和健康状况

```sh
npu/npu health                               # 卡住的线程、ping、送 CPU 通路的计数
npu/npu stats --save /tmp/a.json             # 原版的 60 个计数器（#48）
...                                          # 做实验
npu/npu stats --diff /tmp/a.json             # 只看变化
```

### 读写 SE 表

```sh
npu/npu se sdt 122                           # 表定义
npu/npu se read 34 0                         # 读表项（安全读法，不会清零）
npu/npu se write SDT IDX W0 W1 W2 W3         # 写表项（十六进制，按 se read 打印的顺序）
npu/npu mac50 add 02:00:00:00:00:02 5        # MAC 表 #50
```

### 快转规则（原版微码自带的 HGU 快转，见手册 7.5 节）

测试时用假源 MAC 发原始帧。按下面先登记两条 MAC 表项，测试帧才会进快转：

```sh
npu/npu mac50 add 02:00:00:00:00:02 5        # 假源 MAC 在 LAN1
npu/npu mac50 add 00:d0:d0:61:62:01 0        # 板子 MAC 指向上联口
```

NAT44：五元组匹配，改写 MAC、IP、端口，从 LAN1 发回：

```sh
npu/npu fast add --sip 10.1.1.2 --dip 10.2.2.2 --proto udp --sport 40001 --dport 7781 \
    --out-port 5 --set-sip 10.8.8.8 --set-dip 10.9.9.9 \
    --set-smac 00:d0:d0:61:62:01 --set-dmac 00:e0:41:68:0d:86 --set-sport 0x1111 --set-dport 0x2222
npu/npu send 10.1.1.2 10.2.2.2 40001 7781 --stats   # 发 3 帧，打印弹回来的包和计数变化
npu/npu fast list
npu/npu fast del --all
```

其他规则：

- **NAT66**：地址写 IPv6 即可，键里的摘要由工具自动计算。
- **DS-Lite**：`npu/npu fast wanlink 3 --dslite 2001:db8::1 2001:db8::2`，再在规则里加 `--wan-link 3`。
- **PPPoE**：`fast wanlink 4 --pppoe 0x1234`。
- **VLAN**：`--vlan-push 0x8100:3:100`。

各表的位布局用 `fast layout`、`fast dump TABLE IDX` 查看。

做完记得删掉测试用的 #50 表项：`npu/npu mac50 del 02:00:00:00:00:02`、`npu/npu mac50 del 00:d0:d0:61:62:01`。

### 试指令语义：测试台

`build/npu-exp/oracle/bench.py` 把"原版微码 + 测试块"整份加载，Mac 发 UDP，NP 执行测试块后把寄存器写回包里，每秒约 1.4 万个测试。`probe.py`、`flipreport.py` 都建在它上面。用法写在 `bench.py` 的文件头里，实验 70–100 的脚本都是例子。

### 逆向驱动

```sh
npu/npu ko dis                               # 生成 build/npu-re/np_133.dis
npu/npu ko fn se_plcr_init                   # 看一个函数，字符串常量已经替换成原文
npu/npu ko str "me_id(%d)"                   # 哪些函数引用了这个字符串
npu/npu ko var g_fpga_system_clk             # .data 变量的初值
```

注意：静态函数没有符号，反汇编里会被算到前一个有名字的函数名下。

## 4. 命令一览

运行 `npu/npu -h` 看全部命令，`npu/npu 命令 -h` 看某个命令的参数。

| 类别 | 命令 |
|---|---|
| 离线 | `dis`、`asm`、`flow`、`patch`、`ko` |
| 环境 | `config`、`mac-sync`、`selftest` |
| 板子 | `sh`（短命令）、`run`（推送脚本执行，每条命令后附 dmesg）、`health`、`stats`、`load`、`restore`、`reboot`（`--lan-only`：板子已自行重启时只拉起 LAN）、`inst` |
| 查表引擎 | `se sdt/read/write/hash-add/hash-del`、`mac50` |
| 快转 | `fast add/del/list/wanlink/dump/lastkey/digest/layout`、`send` |

Python 里也可以直接用：`sys.path.insert(0, 'npu')`，然后 `from npukit import board, acl, frames`。

## 5. 目录

| 位置 | 内容 |
|---|---|
| `npu/npu`、`npu/npukit/` | 命令行和库：`config`（路径和配置）、`link`（与 Mac、串口、LAN 通信）、`board`（板上操作）、`acl`（快转的布局和规则）、`frames`（测试帧）、`selftest` |
| `npu/mac/` | 在 Mac 上运行的脚本：`ser.py` 串口、`push.sh` 推文件、`board_reboot.py` 安全重启、`rawtest.py` 原始帧收发、`pump.py`/`pace.py` 测试台发包。用 `npu mac-sync` 同步过去 |
| `npu/tests/` | 离线测试（测试向量取自板上实测） |
| `build/npu-re/` | 离线微码工具链：`npisa.py`（指令格式，权威定义）、`npdis.py`、`npasm.py`、`npnames.py`、`np_flow.py`、`ko_tool.py`，带测试 |
| `build/npu-exp/` | 历次实验的脚本和日志，见其中的 `README.md`。`oracle/bench.py` 和 `snippet.py` 仍然是可复用的工具 |
| `npu/state/` | 本地运行状态（已下发规则的删除句柄），不进 git |

## 6. 已知限制

- 只在一套环境上用过：这块 ZX279133 ONU、原厂驱动 `np_133.ko`、原版微码 `mcode_133.bin`。换设备要重新核对端口号、表号和时钟，见手册各章的"证据"标注。
- 串口很慢，每条命令要 10 秒以上。批量操作请用 `npu run` 或 `link.script()`，不要一条一条发。
- 快转的剥头方向、6rd／L2TP／VxLAN 加头、SFU 路径还没在板上验证（手册第 11 节）。
