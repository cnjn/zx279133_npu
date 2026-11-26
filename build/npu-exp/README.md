# build/npu-exp：上板实验的脚本和记录

这里是实验 4–101 留下的脚本、日志和原始数据。每个实验的结论写在 [NPU_MCODE.md](../../NPU_MCODE.md)，按实验编号查。日常操作请用 [npu/README.md](../../npu/README.md) 里的 `npu` 命令。

## 仍然可复用的工具

| 文件 | 用途 |
|---|---|
| `oracle/bench.py` | 测试台：把"原版微码 + 测试块"整份加载，Mac 发 UDP，NP 执行测试块后把寄存器写回包里，每秒约 1.4 万个测试。用法写在文件头。Mac 地址等环境参数从 `npu/config.toml` 读 |
| `oracle/probe.py`、`oracle/flipreport.py` | 建在测试台上：找出每个输出位依赖哪个输入位；对指令字逐位翻转，列出每一位的作用 |
| `oracle/plcr_model.py` | 限速器（#252）的令牌模型，可以重放 `oracle/runs/exp100_*.json` |
| `snippet.py` | 在指定 PC 汇编一段带标签的代码并挂钩，生成 apply/restore 命令（`npu patch` 调的就是它） |
| `regdump.py`、`regdump_decode.py`、`flags_table.py` | 寄存器、内存、标志的转储探针，以及抓包结果的解析 |
| `udp_reflector.s` | 完整的自定义功能示例：UDP 7777 端口的包整个在 NP 里反射（手册第 10 章） |
| `acl/` | 实验 101 的脚本；功能已经并入 `npu/npukit`（`frames.py`、`acl.py`） |

## 只作记录的部分

- `exp*.py`、`exp*.sh`、`scan2.py`、`blockscan.py` 等：一次性实验脚本，里面写死了当时的环境（Mac 上的 `/tmp/ontser.WZUED8`、固定 IP）。可以照着思路改写，不要直接重跑。
- `*.log`、`*.txt`、`oracle/runs/*.json`：原始输出，是 NPU_MCODE.md 里各条结论的证据，请保留。
- 实验 80、85 的脚本（以及实验 100 期间的一次表 #25 扫描）用过 `se_debug/cpu_get_eram_by_table_width`。后来发现它读完会把表项清零（见 [npu/SAFETY.md](../../npu/SAFETY.md)），不要照抄。
