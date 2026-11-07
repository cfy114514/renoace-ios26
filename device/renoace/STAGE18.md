# 第十八阶段：reserved-memory / handoff 离线审计

本阶段比较手机实测 DT 的 22 个 reserved-memory 区域与 Aloha `oppo-pclm10` 的活动内存描述符。它没有授权任何 XNU allocator，也没有构建、写手机或启动 USB/DMA。

```powershell
python tools/audit_renoace_memory_handoff.py
```

报告保存在 `out/analysis/renoace-memory-handoff.json`。审计发现 `cont_splash_region` 和 `disp_rdump_region` 是同一段 `0x9d000000/0x02400000` 的重复别名；Aloha 的 `PIL_REGION`、`QTEE/TZApps` 和显示描述符会覆盖多个实测 carve-out。报告生成的 free ranges 只排除了已测 reserved-memory，仍是 provisional，不能替代完整 EFI/固件 ownership map。
