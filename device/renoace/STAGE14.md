# 第十四阶段：P11 虚拟定时器恢复契约

本阶段只做源码、反汇编和主机验证，没有手机、MMIO、镜像或远程操作。P11 的第二次 PE 返回边界已经冻结；这里解决继续到 `fiq_context_init(TRUE)` 前必须补上的状态契约。

固定源码 `machine_routines.c` 的 `_enable_virtual_timer()` 写入 `CNTV_CTL_EL0=1`，随后按源码还会写 `CNTP_CTL_EL0=IMASKED`。当前实际内核的 `fiq_context_init` 在 DAIF 仍被屏蔽的分支中跳过了 physical timer 的冷路径，只执行 `MSR CNTV_CTL_EL0,X8`，地址 `0xfffffff007509498`、原字 `0xd51be328`；这由当前 Mach-O 反汇编直接核对。不能把这次编译结果推广成所有配置的 physical timer 行为。

继续 P11 时，桥必须在进入 `fiq_context_init` 前保存：

- `CNTV_CTL_EL0`，包括 enable、masked 和只读 `ISTATUS` 见证；
- `CNTV_CVAL_EL0` 的绝对比较值；
- `CNTP_CTL_EL0`，因为源码函数可能在另一 DAIF/编译分支写它；若要独立解释 physical `ISTATUS`，还要读取 `CNTP_CVAL_EL0` 或直接保存其原始 `ISTATUS` 见证；
- 必要的 `CNTVCT_EL0` 起始值，用于记录模型时间变化，而不是恢复 TVAL。

恢复顺序应保持 DAIF 屏蔽：先写回 `CNTV_CVAL_EL0`，再写回原始 `CNTV_CTL_EL0`，读取回所有寄存器并记录一致性；随后恢复已有 P07/P09 系统寄存器、栈、FP/SIMD、根和 VBAR。`CNTV_TVAL_EL0` 是相对且随时间变化的值，不能作为绝对恢复值。若原始控制值允许 timer 已启用或 `ISTATUS=1`，恢复后仍可能产生待处理状态，因此在返回 Linux 前必须保持 DAIF 屏蔽并明确记录 pending 见证；若目标是让原 Linux 接管 timer，则保存的控制状态必须与进入前完全相等。

P11 的成功门槛是：第二次 PE 调用/返回见证、上述 timer 保存/恢复等式、physical timer 分支是否实际执行的分支记录、DAIF/VM 根/栈/FP 状态等式，以及 Linux 返回和原 recovery 恢复。越过 `fiq_context_init` 后再继续 `machine_init`、scheduler 或 `PE_init_iokit`，还需要实际 timer/IRQ 路径和更大的 RX/日志布局审查。

证据：[P11 静态检查器](../tools/validate_renoace_p11_checkpoint.py)、[P11 检查结果](../../out/analysis/p11-second-pe-static.json)、[P11 原始路径分析](../../out/analysis/p11-post-vm-checkpoint.md)。完整 iOS、XNU 运行期电脑连接、DMA/IOVA 和真实 IRQ 仍未证明。

离线事件回放：[replay.py](../../out/p11-second-pe-model/replay.py)、[replay.json](../../out/p11-second-pe-model/replay.json)。它在真实内核字节上复核事件顺序，并确认 `arm_init` 到 FIQ 调用前没有提前写 `CNTV_CTL_EL0`；它没有执行 XNU 或手机。

主机契约模型：[validate_renoace_timer_contract.py](../../tools/validate_renoace_timer_contract.py)。它覆盖绝对 `CVAL` 保存/恢复、`CNTV_CTL_EL0` 与 `CNTP_CTL_EL0` 的可写位、只读 `ISTATUS` 的 pending 见证、完整 DAIF 屏蔽及精确恢复和半范围歧义拒绝；八个正/负用例均通过。运行：

```powershell
python tools/validate_renoace_timer_contract.py
python -m unittest discover -s tools/tests -p 'test_*.py'
```

这是主机模型证据，`hardware_tested=false`；它不会把 TVAL 当作绝对恢复值，也不会声称已经验证真实 timer、IRQ 或手机返回路径。

P11 桥的离线候选现在在 `mmu_bridge.S` 中保存 `CNTV_CTL_EL0/CVAL_EL0`、`CNTP_CTL_EL0/CVAL_EL0` 及入口 `ISTATUS`，并在恢复阶段强制 DAIF 屏蔽，先写绝对比较值、再写控制位，最后读取回控制/比较值和新的 `ISTATUS` 见证。`xnu_control.c` 只接受可写控制位和两个绝对 `CVAL` 精确恢复，并记录 timer 恢复字段。固定 Linux NDK 30.0.14904198 已由 [`setup_renoace_ndk.py`](../../tools/setup_renoace_ndk.py) 下载并以 SHA-1 `26b746e5…` 核验；当前云环境已真实编译 `mmu_bridge.bin`（10048 字节，SHA-256 `39300f04…`）和 `vm_gate.bin`（460 字节，SHA-256 `e4765921…`）。

只编译桥和 RX gate（不读取手机或私有 boot/recovery 镜像）：

```bash
python tools/setup_renoace_ndk.py --check
python tools/build_renoace_p11_probe.py --bridge-only
```

本次已在本机载入上述被 `.gitignore` 排除的只读输入、冻结 seed 和上游 `references/`，完成完整 P11 构建与指令模型。构建 ID 为 `082d5a90257c6a45`，Image SHA-256 为 `8930b4b0063d26ca107c0b5dbda25d955c9d9a9d957b31c86dfa32c143dc6e8e`，RX gate 为 460 字节、私有补丁 155 个。模型结果位于 `out/xnu-p11-probe/native-p11-tests.json`，`passed=true`；正向事件包含完整 VM 返回、第二次 PE 返回、`fiq_context_init` 返回 gate、旧根恢复、identity 返回和 Linux bridge 返回。该模型仍是离线指令模型，`hardware_tested=false`。

复现命令：

```powershell
python tools/setup_renoace_ndk.py
python tools/build_renoace_p11_probe.py
python device/renoace/xnu_p11_probe/test_instructions.py --build out/xnu-p11-probe
# Include all eight refusal/fault peers:
python device/renoace/xnu_p11_probe/test_instructions.py --build out/xnu-p11-probe --all-cases
```

第二次 PE 返回 gate 已完成第三阶段离线正向验证：恢复被替换的 `mov x0,x19` 后继续原始 `arm_init`，并在 `fiq_context_init` 返回地址 `0xfffffff007b33fe8` 进入 RX gate；该 gate 恢复原始页表并回交 Linux。负向拒绝用例、真实 `fiq_context_init`、IRQ 投递和手机执行仍未验证。
