# iOS on OPPO Reno Ace — research workspace

2026-11-07：以 **UniXNU 的 iOS 26 / 普通 arm64 兼容分支**作为研究主线，结合 `UniXNU-zeta` 的转换方案、`ios-flame` 的 SM8150 驱动及 OPPO 官方 19081 源码交叉适配。

当前完成：专用 XNU 云编译、正式零基址源码修复，以及 P04–P08 实机 MMU、真实异常、早期 C、完整 VM 和 Device 映射。**P09 已在实机有条件地读到 Synopsys DWC3.1 控制器身份与状态，P10 又完成了纯 SMMU-only GR0 双轮/94 行只读观察并恢复 YAAP**；原 recovery 和清理核验通过。**USB 枚举/DMA及 XNU 运行期电脑连接仍未实现，完整 iOS 尚未开机；完整中断、调度、IOKit及驱动仍待验证。**

离线验证：P01 实际 ARM64 指令模型17项、XNU 装载布局/ADT/boot_args 校验10项、P03 完整装载模型9项和独立内存操作190项通过。模型与布局检查不等于手机启动证明。

- [研究结论和项目比较](RESEARCH.md)
- [Reno Ace 适配顺序](device/renoace/BRINGUP.md)
- [第二阶段记录与待执行方案](device/renoace/STAGE2.md)
- [P01 实机结果与恢复记录](device/renoace/STAGE3.md)
- [P02 实机日志桥接成功](device/renoace/STAGE4.md)
- [P03 实机入口控制与装载预算记录](device/renoace/STAGE5.md)
- [专用内核云编译成功与 MMU 交接准备](device/renoace/STAGE6.md)
- [P04 实机 MMU 与 arm_init 入口验证](device/renoace/STAGE7.md)
- [P05 实机 BRK 异常与返回验证](device/renoace/STAGE8.md)
- [P06 实机早期 C、设备树与 PE 初始化](device/renoace/STAGE9.md)
- [P07 实机完整 VM 初始化与 RX 恢复](device/renoace/STAGE10.md)
- [P08 实机设备映射与 USB 时钟只读快照](device/renoace/STAGE11.md)
- [P09 实机 DWC3.1 条件只读识别](device/renoace/STAGE12.md)
- [P11 第二次 PE 初始化的离线边界](device/renoace/STAGE13.md)
- [P11 虚拟定时器恢复契约](device/renoace/STAGE14.md)
- [后续 USB 连接方案（尚未执行）](device/renoace/USB_CONNECTION_PLAN.md)
- [Aloha PCLM10 离线移植审计](device/renoace/STAGE16.md)
- [USB EP0 连接契约离线模型](device/renoace/STAGE17.md)
- [reserved-memory / handoff 离线审计](device/renoace/STAGE18.md)
- [iOS 用户态输入离线清点](device/renoace/STAGE19.md)
- [GENI-I²C PIO-only 移植契约](device/renoace/STAGE22.md)
- [UniXNU GENI-I²C / S3706 接入路径](device/renoace/STAGE23.md)
- [UniXNU 驱动缺口离线审计](device/renoace/STAGE20.md)
- [S3706 I²C 协议离线提取](device/renoace/STAGE21.md)
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

查看配置（不会启动手机；当前 source checkout 需要显式绑定其 Git worktree）：

```powershell
$src = (Resolve-Path references/UniXNU-ios26).Path
$env:GIT_DIR = Join-Path $src ".git"
$env:GIT_WORK_TREE = $src
python (Join-Path $src "unixnu") defconfig renoace_research_defconfig -D device/renoace --out out/unixnu
python (Join-Path $src "unixnu") status -D device/renoace --out out/unixnu
```

`board.example=true` 表示资料尚未足以构建实机镜像，沿用上游的构建拒绝机制。不要只移除此标志就运行构建或上游其他设备的启动脚本。
