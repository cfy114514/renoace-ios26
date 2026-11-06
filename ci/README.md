# Reno Ace 内核 CI

这个手动工作流使用 GitHub 托管的 `macos-26`、Xcode26.6 和 Python3.12，用户无需自备 Mac。**目前只完成本地准备和验证，尚未在云端运行。**

工作流固定检出 `none24smu/UniXNU` 提交 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d` 及其子模块，以两个并行任务编译 XNU12377 内核。Actions 本身也固定到已查证的完整提交 SHA。触发方式只有 `workflow_dispatch`，权限只有 `contents: read`，没有任意 shell 输入。

`tools/prepare_renoace_kernel_ci.py` 只暂存以下七个文件：

- `device/renoace/board.toml`
- `device/renoace/feeds.toml`
- `device/renoace/configs/renoace_research_defconfig`
- `device/renoace/drivers/ArmCpu/` 中的 `ArmCpu.cpp`、`Info.plist`、`LICENSE`、`README.md`

仅临时副本的 `board.example` 被设为 `false`，并加入明确的内核输出路径；原始设备文件保持不变。准备程序拒绝带 prelink 的源配置。CI 仅执行 `build kernel`，不制作 IPSW、根文件系统或手机启动镜像。

产物保留14天，包括 unstripped 内核、构建日志、有效配置、源码与文件哈希、实际 AppleClang/SDK 和其他工具版本。失败时也收集已有日志；工具版本查询缺失或超时不会阻止其余证据收集。SDK、KDK、依赖缓存和设备原始资料不在上传路径中。

本地验证已通过：七文件复制、源文件哈希保持不变、TOML 语义检查，以及实际 UniXNU CLI 的 `defconfig` 和 `status`；`ArmCpu` 解析为 Reno Ace 的设备覆盖。Windows 上的实际框架工具检查明确报告缺少 `xcodebuild`。另验证了工具版本查询超时仍保留失败日志。完整编译和云端工作流行为尚未验证。

在工作流被审阅并放入获授权的专用 GitHub 仓库后，可从 Actions 手动运行 **Reno Ace XNU kernel**。该仓库只需要工作流、准备脚本、本文和上述设备文件，不需要本地工作区历史或手机采集资料。
