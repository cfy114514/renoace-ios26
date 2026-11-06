# iOS on OPPO Reno Ace — research workspace

2026-11-07：以 **UniXNU 的 iOS 26 / 普通 arm64 兼容分支**作为研究主线，结合 `UniXNU-zeta` 的转换方案、`ios-flame` 的 SM8150 驱动及 OPPO 官方 19081 源码交叉适配。

当前完成：项目调查、备份、引导探针、专用 XNU 云编译及 INTID19 机器码核验。**P04 已在实机运行专用内核的原始建表代码、开启 MMU，并到达虚拟地址下的 `arm_init` 入口后受控返回**，总耗时约2.80秒。页表、五项 AT/PAR 地址翻译和调用方状态恢复记录均通过。原 recovery 已恢复并正常回到 YAAP。**尚未执行 `arm_init` C 函数体，完整 XNU/iOS 仍未开机。**

离线验证：P01 实际 ARM64 指令模型17项、XNU 装载布局/ADT/boot_args 校验10项、P03 完整装载模型9项和独立内存操作190项通过。模型与布局检查不等于手机启动证明。

- [研究结论和项目比较](RESEARCH.md)
- [Reno Ace 适配顺序](device/renoace/BRINGUP.md)
- [第二阶段记录与待执行方案](device/renoace/STAGE2.md)
- [P01 实机结果与恢复记录](device/renoace/STAGE3.md)
- [P02 实机日志桥接成功](device/renoace/STAGE4.md)
- [P03 实机入口控制与装载预算记录](device/renoace/STAGE5.md)
- [专用内核云编译成功与 MMU 交接准备](device/renoace/STAGE6.md)
- [P04 实机 MMU 与 arm_init 入口验证](device/renoace/STAGE7.md)
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
