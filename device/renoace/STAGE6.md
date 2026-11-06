# 第六阶段：专用内核的云构建准备

2026-11-07。P03 已在实机通过有限入口交接与返回，记录见 `STAGE5.md`。用户没有可用的 Mac，下一轮源代码编译采用 macOS 云构建路线；当前尚未运行云端编译，也没有新的可启动镜像。

## 构建范围

工作流为根仓库的 `.github/workflows/renoace-kernel.yml`，设备准备工具为 `tools/prepare_renoace_kernel_ci.py`。目标是构建未预链接、保留符号的 XNU 内核，以便核对 Reno Ace 的源码覆盖；这与手机刷写和 iOS 用户态制作分别验证。

- 框架固定为 `none24smu/UniXNU` 提交 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d`。
- 设备 feeds 固定 XNU `12377.121.6` / Darwin `25.5.0`，覆盖框架默认的旧 XNU feeds。
- 使用设备目录内的 ArmCpu 实现，其中虚拟定时器 INTID 为本机的 `19`。
- 使用独立的 CI 设备副本和显式内核输出路径；研究设备原有的 `board.example=true` 保留。
- CI 仅手动触发 kernel 构建，保留内核、配置、源码版本、工具链信息及日志。

当前官方 macOS 26 runner 列有 Xcode 26.6，可显式选择 `/Applications/Xcode_26.6.app`。运行时仍需记录实际版本，镜像升级或所需工具链缺失应使构建失败，而非静默换版本。[GitHub runner 软件清单](https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md)

本机能够核对设备副本、配置解析、模块选择和工作流结构。真正的 Xcode/iPhoneOS SDK/KDK 编译必须由云端运行验证；本地检查通过不代表内核已经编译成功。该分支构建器使用 `xcodebuild`、`xcrun` 和 iPhoneOS SDK，Windows Android NDK 无法直接替代此链路。

## 下一个实机检查点

主要目标是进入虚拟地址下的 `_arm_init`，证明原始启动代码已完成页表、内核栈和 MMU 切换。对当前 P03 固定输入，该符号位于虚拟地址 `0xfffffff007be18cc`，文件偏移 `0xbdd8cc`；重新编译后必须按新产物重新解析符号，不能照搬该地址。

当前 P03 的启动参数仅用于七条指令的控制检查，其 ADT 指针和长度为零。推进前需要将有效 ADT、启动参数和相关内存布局接入装载器，并建立能跨越地址转换的返回与故障记录路径。

原始启动代码会改变 VBAR、LR、两个 SP、TCR、TTBR、MAIR 和 SCTLR。开启 MMU 后，原 Linux 诊断桥的低物理地址代码与栈没有自动映射到 XNU 的虚拟地址空间，因此现有 RET 不能直接后移至 `_arm_init`。早期异常向量还有自旋路径，需要先建立可观察的故障处理。

定时器 INTID19 的源码覆盖仍需在新内核中核对编译结果并实机验证。更晚的 GIC、USB、显示、SM8150 UFS、根文件系统和用户态启动仍是独立工作；当前不把继承的 SM8350 存储实现当作本机驱动。

详细的本地证据分别保存在 `out/analysis/p03-next-xnu-startup.md` 和 `out/analysis/renoace-xnu-build-blockers.md`。
