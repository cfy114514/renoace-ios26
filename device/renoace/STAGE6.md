# 第六阶段：专用内核云编译成功

2026-11-07。P03 已在实机通过有限入口交接与返回，记录见 `STAGE5.md`。随后在用户授权的公开专用仓库完成 macOS 云编译，Reno Ace 的 INTID19 修改已在实际机器码中核实。**新内核尚未在手机执行，完整 XNU/iOS 仍未启动。**

## 本轮构建结果

- [源码仓库](https://github.com/cfy114514/renoace-ios26)，构建源码提交 `02920f9cee5dc19f5d7672a902b266a54978aeb2`。
- [成功构建 42271869198](https://github.com/cfy114514/renoace-ios26/actions/runs/42271869198)，所有步骤通过；产物配置保留14天。
- 未剥离内核：`mach.development.bcm2837.unstripped.noctf`，23,005,680字节，SHA-256 `1295a653bc235d0c11d18ea7a0fc155209fd87396118196ecc8b87e8096f68b8`。
- 本地副本：`out/cloud-kernel/42271869198/extracted/`；ZIP 的 SHA-256 与 GitHub 产物 digest 一致，内核 SHA/大小与云端 kernel-manifest 一致。
- 已解析为普通 ARM64 Mach-O 可执行文件，段/节/符号/入口边界检查通过；实际内存跨度为 `0x16f4000`。
- 云端使用 Xcode26.6/17F113、iPhoneOS SDK26.5、AppleClang21.0.0；工具链记录同时区分 PATH 内的 HomebrewClang23.1.4。

七个已发布设备输入与云端源码清单完全匹配，产物中的七个暂存输入也与暂存哈希匹配。Windows 本地 Info.plist/LICENSE 的 CRLF 与云端 LF 只有换行差异，规范化后内容一致。原始研究配置仍保持 example guard；只有 CI 副本加入输出路径并关闭该副本的 guard。

在 `wakeRedistributor` 和 `enableGic` 两处，实际机器码生成 `0x0008ffff`，并追踪到向 `redist+0x10100` 的写入；`interrupt` 将中断号与 `0x13` 比较，对应分支调用 `rtclock_intr`。旧 P03 输入的两处掩码为 `0x0800ffff`、比较为 `0x1b`，已作为负基线核对。这证明定时器修改进入了编译产物，尚不证明实机中断投递或调度正常。

精简构建身份和机器码证据见 `kernel-build-20261107.json`。完整本地报告为 `out/analysis/renoace-compiled-timer19.json` 与 `out/analysis/renoace-cloud-build-validation.md`。

## 构建范围

工作流为根仓库的 `.github/workflows/renoace-kernel.yml`，设备准备工具为 `tools/prepare_renoace_kernel_ci.py`。目标是构建未预链接、保留符号的 XNU 内核，以便核对 Reno Ace 的源码覆盖；这与手机刷写和 iOS 用户态制作分别验证。

- 框架固定为 `none24smu/UniXNU` 提交 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d`。
- 设备 feeds 固定 XNU `12377.121.6` / Darwin `25.5.0`，覆盖框架默认的旧 XNU feeds。
- 使用设备目录内的 ArmCpu 实现，其中虚拟定时器 INTID 为本机的 `19`。
- 使用独立的 CI 设备副本和显式内核输出路径；研究设备原有的 `board.example=true` 保留。
- CI 仅手动触发 kernel 构建，保留内核、配置、源码版本、工具链信息及日志。

当前官方 macOS 26 runner 列有 Xcode 26.6，可显式选择 `/Applications/Xcode_26.6.app`。运行时仍需记录实际版本，镜像升级或所需工具链缺失应使构建失败，而非静默换版本。[GitHub runner 软件清单](https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md)

本机验证了设备副本、配置解析、模块选择、工作流结构和 actionlint。首次云触发暴露了 job env 不允许引用 runner context 的问题，修正输出路径后，真实 Xcode/iPhoneOS SDK/KDK 编译及产物检查通过。该分支构建器使用 `xcodebuild`、`xcrun` 和 iPhoneOS SDK，Windows Android NDK 无法直接替代此链路。

## 下一个实机检查点

主要目标是进入虚拟地址下的 `_arm_init`，证明原始启动代码已完成页表、内核栈和 MMU 切换。P03 旧输入的该符号位于 `0xfffffff007be18cc`；本轮新内核已重新解析为 `0xfffffff007b334b8`。新入口为 `0xfffffff007503488`，文件偏移 `0x4ff488`。两份产物布局不同，后续按新哈希和新符号生成装载/检查点数据。

当前 P03 的启动参数仅用于七条指令的控制检查，其 ADT 指针和长度为零。推进前需要将有效 ADT、启动参数和相关内存布局接入装载器，并建立能跨越地址转换的返回与故障记录路径。

原始启动代码会改变 VBAR、LR、两个 SP、TCR、TTBR、MAIR 和 SCTLR。开启 MMU 后，原 Linux 诊断桥的低物理地址代码与栈没有自动映射到 XNU 的虚拟地址空间，因此现有 RET 不能直接后移至 `_arm_init`。早期异常向量还有自旋路径，需要先建立可观察的故障处理。

定时器 INTID19 已核对编译结果，仍需实机验证。更晚的 GIC、USB、显示、SM8150 UFS、根文件系统和用户态启动仍是独立工作；当前不把继承的 SM8350 存储实现当作本机驱动。

详细的本地证据分别保存在 `out/analysis/p03-next-xnu-startup.md` 和 `out/analysis/renoace-xnu-build-blockers.md`。
