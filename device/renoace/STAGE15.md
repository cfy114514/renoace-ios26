# 第十五阶段：P10 SMMU 只读契约

本阶段先建立离线 P10 SMMU 读取契约，未启动手机、USB 或 DMA。

固定边界为 apps-SMMU GR0 `0x15000000/0x1000`，只允许读取 `sCR0`、`IDR0`、`IDR1` 以及能力声明范围内的 `SMR`/`S2CR`。契约不读取 context bank、TTBR 或故障页，不写任何 SMMU 寄存器，也不宣称 DMA 所有权。

源码：[smmu_snapshot.h](xnu_smmu_probe/smmu_snapshot.h)、[smmu_snapshot.c](xnu_smmu_probe/smmu_snapshot.c)。构建命令：

```powershell
python tools/build_renoace_smmu_snapshot.py
python tools/test_renoace_smmu_probe.py
python -m unittest tools/tests/test_smmu_probe_source_model.py
```

当前结果：AArch64 对象 `out/xnu-smmu-snapshot/smmu_snapshot.o` 已编译，主机模型 5/5 通过，证据为 `out/analysis/p10-smmu-source-model.json`。模型覆盖稳定双轮、变化拒绝、零能力拒绝、SMS0 原始模式和源页不变性。

手机前置核对发现 YAAP root 没有 `/dev/mem`；Toybox `devmem` 对 `0x15000000`、`0x15000020`、`0x15000024` 均无法读取。因此没有真实 SMMU 快照。native XNU gate、FDT 二进制 raw-record 布局、模型绑定和可恢复 recovery carrier仍待完成；在这些门槛完成前不启动手机 SMMU、USB 或 DMA。
