# 第二十二阶段：GENI-I²C PIO-only 移植契约

本阶段把 Linux DTS 的 `qupv3_se17_i2c` 资源和 S3706 访问顺序固定成合成契约，没有操作 XNU、MMIO、GPIO、I²C、USB、DMA 或手机。

```powershell
python tools/test_renoace_geni_i2c_contract.py
```

模型固定 `0xc80000/0x4000`、GIC SPI 373、`se-clk/m-ahb/s-ahb`、7-bit 地址 `0x20`，以及上电、reset、页选择 `0xff`、F01/F12/F34/F51/F54 发现、F12 触点帧读取、停止和反向掉电顺序。首版明确禁止 DMA，直到 SMMU ownership/IOVA 另行证明。

Linux DTS 还记录了 QUPv3 wrapper stream `0x7a3`、GPI DMA stream `0x7b6` 和 `0x100000/0x100000` IOVA 范围；这些值已写入 `s3706-binding.toml`，只作为未来 ownership 审核输入，当前不会启用。

结果保存在 `out/analysis/renoace-geni-i2c-contract.json`。这为未来 XNU transport 提供边界，但当前仍没有可编译的 UniXNU GENI-I²C/S3706 驱动。
