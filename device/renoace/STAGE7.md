# 第七阶段：P04 已在实机完成原始 XNU MMU 启动并返回

2026-11-07，Asia/Shanghai。**P04 已在 Reno Ace 上通过原始 XNU 页表构造、MMU 开启和高虚拟地址 `_arm_init` 入口检查，经私有观察点与恒等映射返回诊断桥，再继续原 Linux。** 实机记录的构建身份、CRC32、传输 SHA-256、地址翻译和返回状态检查全部通过。原 recovery 已恢复并读回核对，boot、dtbo、vbmeta 与试验前一致。

本轮使用第六阶段云编译的新内核。检查点停在 `_arm_init` 的第一条指令，其 C 函数体尚未执行；完整 XNU、定时器中断投递、驱动初始化及 iOS 用户态启动仍未建立。

| 身份 | 本次值 |
|---|---|
| 构建编号 | `6941903d95f8c58a` |
| 输入 XNU SHA-256 | `1295a653bc235d0c11d18ea7a0fc155209fd87396118196ecc8b87e8096f68b8` |
| 编译后 Image SHA-256 | `55e55529997728dbc9ad5f44d1b313c15cd9c7d688cc0e141fd5573c52846c49` |
| recovery 载体 SHA-256 | `771809126607081aa595e8f4f97e7b7c01071249cd0f684ac2bfb591ed93a963`，写入后分区读回一致 |
| 实机会话 | `local-device/p04-xnu-entry-20261106T200632Z/`，目录时间为 UTC |
| 原始记录 | 会话下 `entry-log/probe-log.bin`，3,743 字节 |
| 记录 SHA-256 | `e08a8a9a8339376e355fac298d8c7f04f91ab7788c723877b5a2a0641510480b` |

装载器完成源内核 CRC、段复制、BSS 清零和目标复核，启动参数指向本次生成的 10,560 字节 ADT。私有桥位于所用物理内存窗口内，原始 XNU 启动代码实际建立页表与内核栈，表检查通过 39 组预期映射后继续执行原始 SCTLR 写入和 ISB。

| 实机检查点 | 记录值 |
|---|---|
| 总结果 | `xnu_status=0`，`xnu_attempted=1`，`xnu_returned=1` |
| 页表检查 | `mmu_guard_entered=1`，`mmu_guard_passed=1`，`mmu_guard_checks=0x27`（39） |
| MMU 与缓存 | `mmu_sctlr=0x3454593d`，M/C/I 均为 1 |
| 翻译配置 | TCR=`0x22a51a251a`，TTBR0=`0x1801b6000`，TTBR1=`0x1801b7000`，MAIR=`0xc0804ff00bb44ff` |
| 高地址入口 | `_arm_init=0xfffffff007b334b8`；观察点 PC=`0xfffffff008805018` |
| 向量基址 | MMU 开启后的 VBAR=`0xfffffff007500000` |
| 内核栈 | SP_EL0=`0xfffffff007dc0000`，SP_EL1=`0xfffffff007dc8000`，SPSel=`0` |
| 恒等映射返回点 | PC=`0x181805214` |
| 返回检查 | `mmu_config_verified=1`，`mmu_state_verified=1`，`mmu_entered=1`，`mmu_returned=1` |

观察点用实际 `AT` 指令检查代码、启动参数、两个栈顶及恒等映射返回地址。五项 PAR_EL1 的故障位均为 0，物理页与构建布局一致：代码及返回页 `0x181805000`、参数页 `0x1816f8000`、SP_EL0 栈顶页 `0x180dbf000`、SP_EL1 栈顶页 `0x180dc7000`。返回后保存/恢复的 TCR、TTBR0/1、MAIR、两个 SP 和 SPSel 相同；外层 SP、VBAR、SCTLR、NZCV、DAIF 和 OSLSR 的前后记录也一致。此次没有捕获异常，`mmu_fault_depth=0`、`mmu_bootstrap_fatal=0`、`mmu_budget_expired=0`。

15 秒预算下，实机计数器为 19,200,000 Hz，`xnu_elapsed_ticks=0x3339d3d`，换算 **2.797616510416667 秒**。这是装载、校验和受控交接的总耗时；记录的 `entry_call` 阶段为 0.0025465625 秒。ADB 在启动请求后约 44.421 秒重新出现，该间隔还包含固件和 Android 启动。

输入 Mach-O 保持原哈希；装载后的私有内存副本共有 **37 处单指令修改**：低/高向量各 16 个入口、`_arm_init` 观察点、页表完成检查点、页表池溢出返回点，以及两处 VBAR 时序修改。高 VBAR 的原写入暂改为 NOP，保留物理 VBAR 跨越 MMU 开启；在原始 SCTLR/ISB 之后的辅助段核对 M/C/I、安装高 VBAR、重放被替换的 MOVK，再继续原启动流。桥自身另有两处返回分支重定位。这一范围不能描述为完全未修改的 XNU 连续启动，也没有执行 `_arm_init` 的 C 函数体。

刷写前的完整指令模型在 Unicorn 2.1.4 的 **CPU_MAX 和 A72 各通过 8/8**：正常交接、私有补丁缺失、源 CRC 错误、保留窗口冲突、页表描述符错误、装载预算耗尽、页表检查期限耗尽，以及显式注入的 MMU 前故障。模型执行实际装载器和 XNU 建表代码，只映射物理 RAM，使用原生页表遍历；没有通过 API 映射高虚拟别名，也没有替换 TCR/TTBR/SCTLR/AT 指令。返回时 x1–x30、系统寄存器和栈严格比较，x0 检查返回状态；PSTATE 的瞬态 BTYPE 单独断言 MAX `2→0`、A72 `0→0`，其余位严格相同。普通 BLR/STR/RET 独立控制复现了该 BTYPE 行为。

模型中的 CNTVCT 进度为确定性模拟，模型耗时不作为实机性能证据。`injected_pre_mmu_fault` 显式设置异常状态并转入向量，验证的是故障桥处理及返回；Unicorn 的原生异常向量投递尚未验证，本次无异常的实机成功也未验证真实故障投递。CPU 特征、缓存与互连效果、固件内存归属不由模型结果替代。当前模型报告位于 `out/xnu-mmu-probe/cpu-max/`、`cpu-a72/` 和 `cpu-model-coverage.json`；两套结果绑定同一测试源码 SHA-256 `e4ebd1c5c78066c101f9d111143a93087491f7323819881ce2312226bbcaba67`。

打包前还完成独立源码/编译产物审查、131 项桥接 ABI 检查、190 项内存原语检查，以及当前 Image、CPIO、ADT、DTB、内核身份和 ABL 装载边界复核。证据不匹配等 12 种打包失败条件均被拒绝。对应报告见 `out/xnu-mmu-probe/package-evidence.json`、`package-gate-tests.json` 及 `out/analysis/p04-independent-integration-review.json`；这些离线报告与上述实机记录分别保留。

取回记录后，原 recovery 已写回，SHA-256 为 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`，分区读回匹配。会话的 `state.json` 记录 `restore_required=false`、`original_recovery_restored=true`，boot/dtbo/vbmeta 未变，手机试验暂存目录已移除。原始 `adb reboot system` 请求仍返回 TWRP；随后通过 TWRP 自身的 `twrp reboot` 正常回到 YAAP，已核对 `boot_completed=1`、原 recovery 哈希、诊断属性不存在和暂存目录不存在，`final_original_android_boot_verified=true`。没有直接改写 misc 分区。

本次可返回的成功构建及精确源码副本已冻结在 `out/xnu-mmu-probe-attempt1/`，109 个文件共282,740,803字节；`snapshot-manifest.json` 记录各文件复制前、目标及复制后源哈希一致。后续故障对照或 C 初始化实验使用独立输出，不能覆盖这份已证明的回退基线。
