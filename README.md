# iOS on OPPO Reno Ace — research workspace

2026-11-06：选择 **UniXNU 的 iOS 26 / 普通 arm64 兼容分支**作为研究主线，以 `UniXNU-zeta` 的转换方案、`ios-flame` 的 SM8150 驱动及 OPPO 官方 19081 源码交叉适配。

当前完成：项目调查、源码拉取与固定版本、实机采集和分区副本校验、fastboot 命令实测、P01 引导诊断镜像的本机构建、Reno Ace 定时器中断适配。**P01 尚未刷写或在手机执行，XNU/iOS 仍未启动。**

离线验证：P01 实际 ARM64 指令模型17项通过，XNU 装载布局/ADT/boot_args 校验10项通过。模型与布局检查不等于手机启动证明。

- [研究结论和项目比较](RESEARCH.md)
- [Reno Ace 适配顺序](device/renoace/BRINGUP.md)
- [第二阶段记录与待执行方案](device/renoace/STAGE2.md)
- [实机硬件参数](device/renoace/hardware.json)
- [设备配置](device/renoace/board.toml)
- [源码版本记录](sources.lock.json)

主工作树：`worktrees/UniXNU-renoace`，本地分支 `codex/renoace-ios26`。
设备配置放在 `device/renoace`，遵循 UniXNU 将单机适配独立于通用框架的结构。

`references/` 保存上游参考源码；`local-device/` 保存原始硬件资料、boot/dtbo/recovery/vbmeta，以及 ABL/XBL、persist/modemst1/modemst2/fsg/fsc 的核验副本。二者及构建输出均已排除出根仓库的版本管理。这仍不是 Android 用户数据备份或所有分区的完整镜像。

重新只读采集：

```powershell
python tools/collect_renoace.py --root --boot-images
```

查看配置（不会启动手机）：

```powershell
python worktrees/UniXNU-renoace/unixnu defconfig renoace_research_defconfig -D device/renoace --out out/unixnu
python worktrees/UniXNU-renoace/unixnu status -D device/renoace --out out/unixnu
```

`board.example=true` 表示资料尚未足以构建实机镜像，沿用上游的构建拒绝机制。不要只移除此标志就运行构建或上游其他设备的启动脚本。
