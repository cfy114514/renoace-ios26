# 第十五阶段：P10 SMMU 只读契约

本阶段先建立离线 P10 SMMU 读取契约，未启动手机、USB 或 DMA。

固定边界为 apps-SMMU GR0 `0x15000000/0x1000`，只允许读取 `sCR0`、`IDR0`、`IDR1` 以及能力声明范围内的 `SMR`/`S2CR`。契约不读取 context bank、TTBR 或故障页，不写任何 SMMU 寄存器，也不宣称 DMA 所有权。

源码：[smmu_snapshot.h](xnu_smmu_probe/smmu_snapshot.h)、[smmu_snapshot.c](xnu_smmu_probe/smmu_snapshot.c)。构建命令：

```powershell
python tools/build_renoace_smmu_probe.py
python tools/test_renoace_smmu_probe.py
python tools/test_renoace_smmu_native_model.py
python tools/package_renoace_smmu_probe.py
python tools/test_renoace_smmu_runtime_model.py
python -m unittest tools/tests/test_smmu_probe_source_model.py
```

当前结果：P10 SMMU-only runtime carrier 已离线构建，build `a9b58102cfe98e75`，gate 2024 字节；主机源模型和独立合成 94 行模型均通过。模型验证双轮 94 行、每轮 188 次 descriptor load、CRC/变化拒绝、128 行上限拒绝，并确认入口不再跳入 P09 USB 段。可恢复 carrier `out/xnu-smmu-probe/recovery.img` 已通过 AVB，SHA-256 `eeafc9da9f4d9cf6912f127d9136207799ec77f2ba97f6f2368b89a58a150e8e`，恢复目标 SHA-256 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`。

纯 SMMU-only 实机证据保存在 `local-device/p10-smmu-only-entry-20261107T182228Z/`。XNU 返回成功（`xnu_status=0`）；SMMU 两轮完成（`smmu_status=2`、`stage=2`），硬件报告 `NUMSMRG=94`。两轮 `sCR0=0x270406`、`IDR0=0x4c017e5e`、`IDR1=0x60000038` 一致，94 个 SMR/S2CR 行的两轮 CRC 均为 `0x07d634a4`，每轮 descriptor reads 为 188，记录 SHA-256 为 `4f0ef8ac9d9eda5c113ee7fe02cf28224b012f14fa96343be897293deba01eec`。纯路径没有 USB controller branch、USB reset/传输、DMA 或 SMMU 写入，电脑连接握手仍未验证。carrier 运行后已恢复原 recovery，`sys.boot_completed=1`，recovery/boot/dtbo/vbmeta 均与前置哈希一致，临时文件已删除。

上一版 d317 carrier 的实机证据仍保存在 `local-device/p10-smmu-entry-20261107T175832Z/`，其 USB 字段属于旧的 P09 继承段；本阶段以新的 a9b 纯 SMMU-only 记录为准。

`tools/capture_renoace_p10.py` 提供无写入记录解析；`native-p10-tests.json` 和 `package-evidence.json` 绑定当前离线候选。无论纯 SMMU 运行结果如何，USB reset/传输、DMA、电脑握手和完整 iOS 仍是独立后续范围。
