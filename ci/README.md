# Reno Ace 内核 CI

这个手动工作流使用 GitHub 托管的 `macos-26`、Xcode26.6 和 Python3.12，用户无需自备 Mac。**[正式零基址源码修复云构建已成功](https://github.com/cfy114514/renoace-ios26/actions/runs/42306878464)**，实际源码提交为 `f5ac9b1a95c85a9b9b7b66461016c295dd4952bd`。

新产物 `mach.development.bcm2837.unstripped.noctf` 为普通 ARM64 Mach-O，23,005,792字节，SHA-256 `c361eda7d383619ec76c814a4f2121955547fadaa8235131d6849aa14d995743`。32项独立静态检查确认：完整44+1补丁及其顺序、源码与编译记录、区分合法基址零的 checked API、缺失总线频率保护，以及保留的 INTID19 启用和分派机器码。两个对象哈希来自 CI 记录，产物未附 `.o` 本体；不能把记录当作本地重算结果。新内核的实机执行另行记录。

[首轮有效构建](https://github.com/cfy114514/renoace-ios26/actions/runs/42271869198)的内核 SHA-256 为 `1295a653bc235d0c11d18ea7a0fc155209fd87396118196ecc8b87e8096f68b8`，已用于后续 P04–P06 临时诊断。首次 PE 初始化的实机通过仍属于该旧内核及其明确记录的私有诊断修改，不是新源码产物的运行证明。真实 INTID19 投递和完整 iOS 仍未验证。

工作流固定检出 `none24smu/UniXNU` 提交 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d` 及其子模块，以两个并行任务编译 XNU12377 内核。Actions 本身也固定到已查证的完整提交 SHA。触发方式只有 `workflow_dispatch`，权限只有 `contents: read`，没有任意 shell 输入。

`tools/prepare_renoace_kernel_ci.py` 只暂存以下八个设备文件：

- `device/renoace/board.toml`
- `device/renoace/feeds.toml`
- `device/renoace/configs/renoace_research_defconfig`
- `device/renoace/drivers/ArmCpu/` 中的 `ArmCpu.cpp`、`Info.plist`、`LICENSE`、`README.md`
- `device/renoace/patches/native-arm-io-zero-base.patch`

仅临时副本的 `board.example` 被设为 `false`，并加入明确的内核输出路径；原始设备文件保持不变。准备程序拒绝带 prelink 的源配置。CI 仅执行 `build kernel`，不制作 IPSW、根文件系统或手机启动镜像。

设备补丁固定 SHA-256 为 `b971f39f86c44ea65f6c5f3e546764744bff51eb0dd3c9622f29592469f0ec8c`，XNU 固定为 `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`。补丁把 arm-io 查找成功与物理基址零分开表示，并校验单个 64 位 ranges 元组；缺失 `bus-frequency` 时 CPU/总线比率保持未知（零），不填造时钟值。后续中断和串口 MMIO 消费者仍需板级验证。

准备程序先按 Git blob 核对并完整复制框架 `patches/xnu-12377` 的44个文件，再把设备补丁命名为 `zzzzz-renoace-native-arm-io-zero-base.patch`，放在原有系列之后。`defconfig`、`status`、`fetch`、`build kernel` 都显式传入绝对路径 `--local-module patch:xnu-12377=.../patch-modules/xnu-12377`。这样保留全部上游补丁，也不会写入框架目录或构建树里的默认符号链接。`patch-module-manifest.json` 记录完整45文件及执行顺序；模块 SHA-256 为 `12bd1cd12611540e4ad5f046ba1ec1f18f9fb5e40046c329230fc561ff0a9ce0`，计算输入是按键排序的紧凑 UTF-8 JSON「相对路径→文件 SHA-256」映射。

产物保留14天，包括 unstripped 内核、构建日志、有效配置、源码与文件哈希、实际 AppleClang/SDK 和其他工具版本。构建成功必须再核对实际补丁模块链接、XNU 提交、设备补丁反向检查、三个相关源码哈希，以及 `pe_identify_machine.o` / `pe_init.o` 的哈希和编译记录。`source-compile-manifest.json` 与 `compile-records/` 保留这些证据，编译命令和诊断见 `logs/kernel.log`。失败时也收集已有日志；工具版本查询缺失或超时不会阻止其余证据收集。SDK、KDK、依赖缓存和设备原始资料不在上传路径中。

本轮本地验证已通过：八文件复制、原始设备与框架补丁哈希保持不变、TOML 语义检查，以及实际 UniXNU CLI 的 `defconfig` / `status` 和四条命令的实际模块解析；`ArmCpu` 解析为 Reno Ace 的设备覆盖。对三个相关源文件先依序应用继承的 `native-dt-panic-region`、`native-source-crypto`、`native-verbose-console`，再应用设备补丁，正向与反向检查通过；这不等同于本地完整 XNU 编译。设备补丁的独立验证另有35个已执行宿主测试和 AArch64 目标编译。本轮 actionlint 和新云构建通过；手机运行结果须分别验证。

首轮云构建日志记录 Xcode26.6/17F113、iPhoneOS SDK26.5、AppleClang21.0.0；编译完成不代表内核运行时自检已通过。重编译会改变内核布局，旧内核的地址与私有二进制修补偏移不能直接复用。

专用仓库为 [cfy114514/renoace-ios26](https://github.com/cfy114514/renoace-ios26)，可从 Actions 手动运行 **Reno Ace XNU kernel**。仓库包含工作流、准备脚本、本文和上述设备文件，未上传本地工作区历史或手机采集资料。成功构建的二进制和证据在 Actions 产物中保留14天，本机另有核验副本。
