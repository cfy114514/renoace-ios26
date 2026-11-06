# Reno Ace 适配起点

本文件对应 PCLM10 / OP4A89 / OPPO project 19081，实机硬件事实见 `hardware.json`。这里只把已测量的事实用于配置。已在本机受控执行 XNU 的完整 `arm_vm_init` 并返回 Linux；这仍不是完整内核或 iOS 开机。

最新结果见 [STAGE10.md](STAGE10.md)：P07 使用正式零基址修复内核，实机新页表、RX 返回入口和调用方状态恢复通过，原 recovery 已恢复并正常回到 YAAP。当前 ABL 不支持 `fastboot boot`；受控诊断沿用临时 recovery 覆盖和恢复流程。XNU 运行期间的 USB/电脑交互仍未验证，不能用回交后的 ADB 代替。

## 源码分工

- `worktrees/UniXNU-renoace`：`none24smu/UniXNU` 的 `ios26-ufs-owner-root`，iOS 26 内核、构建工具、通用驱动及固定子模块。
- `references/UniXNU-zeta`：与框架配对的 `cce9be4`，普通 arm64 用户态转换、dyld shared cache 处理和 iOS 26 接口适配参考。
- `references/ios-flame`：SM8150 / Adreno 640 的 XNU 驱动参考。其 iOS 16 补丁不能直接套到 XNU 12377。
- `references/oppo-kernel`：官方 19081 DTS、Synaptics S3706 驱动、时钟及 PMIC 定义。它是 Android 10 源码，实机是 Android 15 定制内核；有冲突时继续核对运行中的 DT 和实际内核。
- `references/aloha`：Project Aloha 的现成 `oppo-pclm10` UEFI 目标，后续需接入 UniXNU/DarwinBoot；没有本机运行证明。

## 已确定的板级差异

| 项目 | Reno Ace 实机 | 适配含义 |
|---|---|---|
| SoC / GPU | SM8150 Plus / Adreno640v2 | 优先借鉴 flame 的同代硬件实现 |
| 触控 | S3706，GENI I²C `0xc80000`，地址 `0x20` | 不能使用 flame 的 ST FTS SPI 驱动 |
| 触控引脚 | TLMM IRQ 122、reset 54；PM8150L GPIO 5 控制 1.8V | 应从官方 S3706 电源和寄存器流程开始 |
| 屏幕 | Samsung SOFEF03F_M，1080×2400，DSC command mode，60/90Hz timing | flame 的 1080×2280、framebuffer/stride/刷新配置不能照搬 |
| splash 保留区 | `0x9d000000`，长 `0x02400000` | 这是保留内存范围，尚不能当作实际扫描帧地址 |
| 内存 | DT 有三个 bank，多处固件 carve-out | 按完整 reserved-memory 计算可用窗口，不能把 8GB 全交给 XNU |
| 按键 | PM8150 GPIO6/7 分别为音量上/下 | flame 的音量下 PON 路径不适用 |
| boot 镜像 | v2，4KB 打包页，gzip(Image)+附加 DTB，同时还有独立 v2 DTB；独立 recovery | 两份 DTB 均保留；Google ABL 的 LZ4/AVB 和 A/B 规则不能移用 |
| UFS | 控制器 `0x1d84000` | 地址相同也不能跳过 PHY、时钟、LUN、SMMU 验证 |

## 接下来的执行顺序

1. **建立能返回 Android 的引导探针。** 第二阶段已测得 unlocked=yes、下载上限768MiB，但 ABL 缺少 `boot` 命令，两个现有内核也无 kexec。P01–P07 已按用户授权执行临时 recovery 覆盖及复原流程，早期方案见 STAGE2。此阶段不接 iOS 根分区。
   固定分支通用打包器只生成 gzip+附加 DTB，不能完整复现当前镜像两份 DTB 的布局。已新增本机专用 P01 打包器，保留附加 DTB、独立 v2 DTB 和 recovery DTBO，并做逐字节回解验证。实际 ABL 已接受本机受控载体，后续每次几何变化仍须复核。
2. **串起最小引导和日志。** 在 Reno Ace 上适配 SM8150 UEFI，或实现与目标 XNU boot_args 兼容的 shim。前者可参考 `UniXNU-guacamole` / Project Aloha；后者可参考 flame。确定 bootloader 留下的显示地址、格式、stride、GIC/定时器、可用 RAM；读取原生 CPU feature registers。先完成可观察的日志，再扩展功能。
3. **建立 XNU 运行期电脑连接，再推进最小 PID 1。** 完整 VM 初始化和异常返回已验证；USB控制台仍关闭。先按本机 GCC/SMMU/PHY 参数验证只读快照、受限 DMA/IOVA 与主机挑战应答，再验证真实定时器中断、调度及单核运行，随后拉起八核。使用自建最小 RAM 根测试，把板级启动问题与 iOS 用户态问题分开定位。
4. **接入 iOS 26.5.2 用户态兼容。** 从本地匹配的 IPSW 输入提取资源，复用经核对的 arm64e→arm64 lowering、dyld cache 和签名/信任处理。完整用户态及 Apple 私有 kext 的 ABI 问题仍需验证；不能只改 Mach-O subtype 或用 iOS 16 内核替换版本号。
5. **适配存储和显示，然后触控。** 先明确系统存储方案、备份与恢复路径，再处理持久化根文件系统。移植 SM8150 UFS、A640/GMU/SMMU、Samsung panel 和 S3706。内核输出、launchd、SpringBoard 出图、触控解锁是不同检查点，应分别记录。

## 明确未完成的事项

已有 Aloha PCLM10 UEFI 参考、专用 XNU 云构建和 P03–P07 实机受控日志，但没有组合成完整 iOS 引导包。尚无已验证的 iOS 根镜像、XNU运行期USB、真实硬件中断和完整调度器/IOKit。没有验证通话、Wi-Fi、蓝牙、相机、音频、充电或休眠。没有分配或写入任何 iOS 存储区。

这次选定的历史分支仍使用 macOS / Xcode 构建路径。本机有 Python、Git、ADB 和 Android NDK；当前 WSL 的 `crb` 实例启动返回 `0xd0000022`。专用 macOS CI 已完成两轮有效 XNU 编译；不能把最新 UniXNU 主线的 Linux 支持直接当成此固定分支已经具备的能力。
