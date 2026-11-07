# 第十三阶段：第二次 PE 初始化的离线边界

P09 实机已恢复并验证；本阶段只做静态离线检查，没有手机、远程、MMIO 或镜像操作。

当前内核 `c361eda7d383619ec76c814a4f2121955547fadaa8235131d6849aa14d995743` 的下一处有意义检查点是第二次 `PE_init_platform(TRUE, &BootCpuData)` 返回后的第一条指令：

- 调用：`0xfffffff007b33fa8`，目标 `_PE_init_platform=0xfffffff007aa4c70`。
- 返回点：`0xfffffff007b33fac`，文件偏移 `0xb2ffac`，原字 `0xaa1303e0` (`mov x0,x19`)。
- 见证寄存器：X19=`0xfffffff007bf6f60` (`BootCpuData`)，X20=`0xfffffff0071b3dc8` (`serialmode`)，X21=`0xfffffff0071b5120`，SP_EL0=`0xfffffff007dbff30`，SP_EL1=`0xfffffff007dc8000`。

这是后续原始初始化的边界证明，不是中断或 USB 证明。当前输入下 `pe_arm_init_interrupts` 仍因合法 SoC 基址为零而走旧值接口的返回路径，未到达 GIC/时基映射。

再往后会调用 `fiq_context_init`，在 `0xfffffff007509498` 写 `CNTV_CTL_EL0=1`。继续越过该指令必须保存/恢复 `CNTV_CTL_EL0` 和绝对 `CNTV_CVAL_EL0`，并控制待处理虚拟定时器/中断；现有 P07/P09 恢复桥没有这部分契约。

可复现检查器：[validate_renoace_p11_checkpoint.py](../tools/validate_renoace_p11_checkpoint.py)。当前检查通过，且篡改返回字的副本会被拒绝；输出：[p11-second-pe-static.json](../../out/analysis/p11-second-pe-static.json)。

后续真正的 P11 候选仍需新的桥接/日志字段、模型覆盖和独立复核。不能把该离线边界当作手机启动、IRQ、DMA、XNU 运行期电脑连接或完整 iOS 证明。
