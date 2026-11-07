# 第十七阶段：USB EP0 连接契约离线模型

本阶段把 `USB_CONNECTION_PLAN.md` 中的首个电脑连接证明固定为离线合成契约，没有操作手机、USB 控制器、DMA 或 IOVA。

```powershell
python tools/test_renoace_usb_connection_contract.py
```

模型覆盖 USB2 EP0 设备描述符请求、带当前 build ID 的 32 字节 nonce challenge/response、页对齐且互不重叠的 setup/event/TRB/response 缓冲区，以及停止顺序：先确认 DMA 静止，再解除 IOVA 和恢复保存状态。负向用例覆盖 nonce 不匹配、缓冲区重叠和非页对齐。

结果保存在 `out/analysis/p12-usb-connection-contract.json`。它是下一次实机工作的输入契约；电脑必须在 XNU 仍运行时观察并匹配 response，真实端点、PHY、SMMU/DMA 所有权和主机枚举仍未验证。
