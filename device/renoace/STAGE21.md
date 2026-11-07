# 第二十一阶段：S3706 I²C 协议离线提取

本阶段从固定 OPPO Linux S3706 驱动提取后续 XNU/UEFI 移植所需的寄存器页选择、功能发现、触点读取、电源和中断路径；没有操作手机或 GPIO/I²C/USB/DMA。

```powershell
python tools/audit_renoace_s3706_protocol.py
```

报告保存在 `out/analysis/renoace-s3706-protocol.json`。驱动使用页选择寄存器 `0xff`，在页 0/1/4 上发现 F12/F01/F34/F51/F54 基址；触点数据从 F12 data base 按每指 8 字节读取；上电顺序为 2.8V、1.8V、延时、reset high，下电顺序相反并拉低 reset。

固定 Linux DTS 还提供了精确的 board binding：`qupv3_se17_i2c`，`0xc80000/0x4000`，GIC SPI 373，QUPv3 wrapper 2 时钟，以及 `synaptics19081@20`、GPIO122/54、`pm8150_l17` 和 1080×2400 资源。该 binding 仍未移植到 XNU/UEFI；真实电源、IRQ 和触点报告也未验证。

对应的机器可读移植输入已保存为 `device/renoace/s3706-binding.toml`。它明确保留 PIO-only、`dma_allowed=false` 和 `xnu_driver_ready=false`，不会被当前 UniXNU 构建自动启用。
