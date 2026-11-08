# 第二十三阶段：UniXNU GENI-I²C / S3706 接入路径

这是实现交接计划，不是已完成的 XNU 驱动。当前没有操作手机、I²C、USB 或 DMA。

## 代码边界

1. 新增 `drivers/NativeGeniI2c`，复用 `NativeGeniSpi` 的 `geni_io` 回调、时钟/状态读取、PIO FIFO、poll/cancel/abort 错误处理和寄存器模型结构。
2. I²C transport 不能复用 SPI 的 opcode、chip-select、word-length 和 full-duplex 语义；需要独立的 7-bit address、START/STOP、TX/RX、NACK/timeout 和 repeated-start 状态机。
3. 新增 Reno Ace board adapter，读取 `device/renoace/s3706-binding.toml`：`qupv3_se17_i2c`、`0xc80000/0x4000`、GIC SPI 373、QUPv3 clocks、pinctrl、GPIO122/54/5 和 `pm8150_l17`。
4. 新增 S3706 protocol layer，保留 Linux 参考中 `0xff` 页选择、页 0/1/4 F01/F12/F34/F51/F54 discovery、F12 每指 8 字节 frame、reset 和电源顺序；通过 `NativeHidInput` 发布触控事件。
5. 首个实现只允许 PIO。`gpi_dma2`、SMMU stream `0x7b6`、wrapper stream `0x7a3` 和 IOVA 范围只作为后续 ownership 输入，不能由触控驱动自动启用。

## 离线测试门槛

- GENI register model 覆盖 protocol/width/status、FIFO TX/RX、START/STOP、NACK、timeout、cancel/abort 和恢复。
- S3706 model 覆盖页切换、基址 discovery、8-byte touch frame、错误响应和 reset/power rollback。
- board binding test 必须绑定 `s3706-binding.toml`、固定 DTS SHA 和 Linux S3706 source SHA；任何地址/IRQ/电源变化都拒绝。
- 静态检查确认没有 DMA enable、SMMU write、USB 操作或未绑定的高地址 MMIO。

## 暂不接入的部分

当前 `board.toml` 仍是 research-only，缺少匹配 iOS IPSW/userland；UniXNU build 也受 Windows/Xcode 和外部引用限制。因此本计划暂不修改 UniXNU build manifest、不生成可启动固件、不做手机验证。完成上述离线模型并获得外部输入后，才进入 XNU 编译和受控硬件验证。
