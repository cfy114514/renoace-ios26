# Reno Ace 内核 CI

这个手动工作流使用 GitHub 托管的 `macos-26`、Xcode26.6 和 Python3.12，用户无需自备 Mac。**[首轮有效云构建已成功](https://github.com/cfy114514/renoace-ios26/actions/runs/42271869198)，新内核尚未在手机启动。**

构建提交为 `02920f9cee5dc19f5d7672a902b266a54978aeb2`。产物 `mach.development.bcm2837.unstripped.noctf` 为普通 ARM64 Mach-O，23,005,680字节，SHA-256 `1295a653bc235d0c11d18ea7a0fc155209fd87396118196ecc8b87e8096f68b8`。下载后的 ZIP/内核哈希、输入清单和有效配置已核对；静态机器码确认两个启用掩码均为 `0x0008ffff`，中断19对应分支调用 `rtclock_intr`。真实中断、MMU/arm_init 和 iOS 用户态尚待验证。

工作流固定检出 `none24smu/UniXNU` 提交 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d` 及其子模块，以两个并行任务编译 XNU12377 内核。Actions 本身也固定到已查证的完整提交 SHA。触发方式只有 `workflow_dispatch`，权限只有 `contents: read`，没有任意 shell 输入。

`tools/prepare_renoace_kernel_ci.py` 只暂存以下七个文件：

- `device/renoace/board.toml`
- `device/renoace/feeds.toml`
- `device/renoace/configs/renoace_research_defconfig`
- `device/renoace/drivers/ArmCpu/` 中的 `ArmCpu.cpp`、`Info.plist`、`LICENSE`、`README.md`

仅临时副本的 `board.example` 被设为 `false`，并加入明确的内核输出路径；原始设备文件保持不变。准备程序拒绝带 prelink 的源配置。CI 仅执行 `build kernel`，不制作 IPSW、根文件系统或手机启动镜像。

产物保留14天，包括 unstripped 内核、构建日志、有效配置、源码与文件哈希、实际 AppleClang/SDK 和其他工具版本。失败时也收集已有日志；工具版本查询缺失或超时不会阻止其余证据收集。SDK、KDK、依赖缓存和设备原始资料不在上传路径中。

本地验证已通过：七文件复制、源文件哈希保持不变、TOML 语义检查，以及实际 UniXNU CLI 的 `defconfig` 和 `status`；`ArmCpu` 解析为 Reno Ace 的设备覆盖。另验证了工具版本查询超时仍保留失败日志。修正 job env 的路径上下文后，actionlint 和真实云端流程均通过。日志记录 Xcode26.6/17F113、iPhoneOS SDK26.5、AppleClang21.0.0；编译完成不代表内核运行时自检已通过。

专用仓库为 [cfy114514/renoace-ios26](https://github.com/cfy114514/renoace-ios26)，可从 Actions 手动运行 **Reno Ace XNU kernel**。仓库包含工作流、准备脚本、本文和上述设备文件，未上传本地工作区历史或手机采集资料。成功构建的二进制和证据在 Actions 产物中保留14天，本机另有核验副本。
