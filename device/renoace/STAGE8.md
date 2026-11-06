# 第八阶段：P05 实机 BRK 异常返回验证

2026-11-07。P04 已经验证原始 XNU 建表、开启 MMU、进入虚拟地址下的 `arm_init` 后返回。P05 在同一条受控桥上把私有 RAM 中的 `arm_init` 首字替换为 `BRK #0x505`，验证真实异常向量和返回路径。

## 实机结果

- 构建：`a1e7af84e519de1d`。
- recovery 载体 SHA-256：`8557d3147492abe7f6b3c5d04262718c86d899c90de22186a8661f9a8b281297`。
- 实机会话：`local-device/p05-xnu-brk-20261106T212751Z/`。
- 原始 FDT 记录：SHA-256 `f9093040a1f268cb44f2d3d0e8fda8e9e04da743d68d81cd1cc8b65395c42406`，3,976 字节；构建身份、CRC 和传输校验通过。
- 受控总耗时：约 `2.7973859375` 秒，计时基准 19.2 MHz。

记录显示真实执行了 BRK 并进入异常桥：

| 字段 | 值 |
|---|---|
| `mmu_status` | `2`，异常路径 |
| `mmu_esr` | `0xf2000505`，BRK immediate `0x505` |
| `mmu_elr` | `0xfffffff007b334b8`，`arm_init` |
| `mmu_exception_slot` | `0` |
| `mmu_fault_depth` | `1` |
| `mmu_spsr` | `0x600003c4`，异常前 EL1t 状态 |
| `mmu_guard_checks` | `39` |
| `mmu_returned` | `1` |
| `mmu_state_verified` | `1` |

页表、MMU 状态、五项 PAR 翻译、栈、调用寄存器和恢复状态均通过；原 recovery 已恢复，boot/dtbo/vbmeta 未变化，试验暂存目录已清理。最终已回到 YAAP，`boot_completed=1`，原 recovery 哈希正确，诊断属性和暂存文件不存在。

## 证据边界

这次记录证明手机上的 BRK 异常进入了本地异常桥，并返回 Linux。P05 的离线模型在 CPU_MAX 和 A72 上各 9/9 通过；模型中异常帧和向量派发部分明确标记为 synthetic，因为 Unicorn 没有提供完整原生异常向量投递证明。手机记录提供了真实异常 ESR/ELR/slot/depth 和返回结果，因此该边界由实机记录补足。

此阶段仍未执行 `arm_init` 的 C 函数体、IOKit、调度器、驱动、根文件系统或 iOS 用户态。下一阶段的最小有意义目标是早期 C 的 PE 初始化返回点；当前 ADT 的 `/arm-io/ranges` 和 XNU 对零 SoC 基址的可用性判断需要先做兼容性修正。早期 C 还会修改 static-if 链接和若干文本指令，且使用 SIMD 寄存器；P06 已准备相应的独立 SIMD 桥，但尚未实机执行。
