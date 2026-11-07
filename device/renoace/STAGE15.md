# 第十五阶段：P10 SMMU 只读契约

本阶段先建立离线 P10 SMMU 读取契约，未启动手机、USB 或 DMA。

固定边界为 apps-SMMU GR0 `0x15000000/0x1000`，只允许读取 `sCR0`、`IDR0`、`IDR1` 以及能力声明范围内的 `SMR`/`S2CR`。契约不读取 context bank、TTBR 或故障页，不写任何 SMMU 寄存器，也不宣称 DMA 所有权。

源码：[smmu_snapshot.h](xnu_smmu_probe/smmu_snapshot.h)、[smmu_snapshot.c](xnu_smmu_probe/smmu_snapshot.c)。构建命令：

```powershell
python tools/build_renoace_smmu_snapshot.py
python tools/test_renoace_smmu_probe.py
python -m unittest tools/tests/test_smmu_probe_source_model.py
```

当前结果：AArch64 runtime carrier 已离线构建，build `d317fb97d721ad81`，gate 2024 字节；主机源模型通过，静态 native artifact model 通过。可恢复 carrier `out/xnu-smmu-probe/recovery.img` 已通过 AVB，SHA-256 `8290c792637114dbd2efae29e8816aa0327cefc203fe87a22a4a35065b1139e8`，恢复目标 SHA-256 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`。

实机证据保存在 `local-device/p10-smmu-entry-20261107T175832Z/`。XNU 返回成功（`xnu_status=0`）；SMMU 两轮均完成（`smmu_status=2`、`stage=2`），硬件报告 `NUMSMRG=94`。两轮 `sCR0=0x270406`、`IDR0=0x4c017e5e`、`IDR1=0x60000038` 一致，94 个 SMR/S2CR 行的两轮 CRC 均为 `0x07d634a4`，记录 SHA-256 为 `ec7d2213d3798fb5a0da918ae500d079dfd461af06f76ade2a44966bfa4efcbe`。没有 SMMU 写入；没有 USB reset、传输或 DMA；电脑连接握手仍未验证。carrier 运行后已恢复原 recovery，`sys.boot_completed=1`，recovery/boot/dtbo/vbmeta 均与前置哈希一致，临时文件已删除。

该载体沿用 P09 的只读 DWC3 inventory 段，因此记录中存在 USB 状态寄存器读取字段；这不是启动、复位、传输或 DMA。`record-summary.json` 和 `state.json` 标明了这一范围及剩余阻碍。
