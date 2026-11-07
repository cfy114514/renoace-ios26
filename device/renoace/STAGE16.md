# 第十六阶段：Aloha PCLM10 离线移植审计

本阶段只比较固定的 Project Aloha `oppo-pclm10` 参考和 Reno Ace 实测资料；没有构建 UEFI、写手机、启动 USB/DMA 或宣称 DarwinBoot/iOS 启动。

审计命令：

```powershell
python tools/audit_renoace_aloha_portability.py
```

结果保存在 `out/analysis/renoace-aloha-portability.json`。参考与实测地址一致：GICD `0x17a00000`、GICR `0x17a60000`、SMMU `0x15000000`、USB0 `0x0a600000`、MDSS `0x0ae00000`、UFS `0x01d80000`；面板参考包含 Samsung SOFEF03F 1080×2400 DSC command mode。实测 reserved-memory 有 22 个区域，不能直接用 Aloha 描述符替换。

当前移植未就绪。Aloha `oppo-pclm10` 源码中没有 S3706/Synaptics/`0xc80000` 触控驱动；`board.toml` 仍保持研究模式，iOS root storage 未分配；UEFI 构建、DarwinBoot handoff、真实显示/触控运行均未验证。下一步需要先补本机触控和完整 reserved-memory/启动交接设计，再考虑受控的 USB EP0/DMA 模型。
