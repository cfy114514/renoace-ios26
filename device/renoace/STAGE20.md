# 第二十阶段：UniXNU 驱动缺口离线审计

本阶段审查已恢复的 UniXNU 子模块和 Reno Ace 实测资源，不构建 XNU、不操作手机、不启动 USB/DMA。

```powershell
python tools/audit_renoace_xnu_driver_gaps.py
```

结果保存在 `out/analysis/renoace-xnu-driver-gaps.json`。现有 `NativeHidInput` 依赖 sheng/SPI touch feed，`NativeGeniSpi` 是 SPI-only；Reno Ace 的 S3706 需要 GENI I²C `0x20`、`0xc80000/0x4000`、GPIO122/54/5、电源和 IRQ binding。`NativeMobileDisplay` 主要描述 sheng/GOP handoff，`NativeUfs` 主要是 sheng/SM8550；UFS 控制器地址虽有 `0x01d84000` 重合，PHY/GCC/SMMU 兼容性仍未证明。

因此目前仍缺 S3706 XNU transport/board binding、SOFEF03F DSC command-mode panel sequence 和 SM8150 Plus UFS ownership。该审计不把地址重合当作驱动可用性。
