# Reno Ace 运行 iOS：第一阶段调查

调查日期：2026-11-06，Asia/Shanghai。范围为公开项目源码、项目自己的启动记录，以及连接到本机的 PCLM10 的只读资料。其他设备的成功记录不等于本机已验证。

后续实机验证与修正见 [第二阶段记录](device/renoace/STAGE2.md)：已找到 Aloha 的 PCLM10 UEFI，确认当前 ABL 不支持 `fastboot boot`，并确认当前镜像有两份 DTB。以下保留第一阶段选型依据。

## 选择结果

结合用户希望采用 iOS 26 的方向，主研究树选择 **`none24smu/UniXNU` 的 `ios26-ufs-owner-root` 分支**，固定在 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d`；配套采用 `UniXNU-zeta` 的 `cce9be4536221b3fac56a9dea0d7ee2a955fd077`。当前目标组合是 **iOS 26.5.2 / 23F84 用户态 + XNU 12377.121.6 + 普通 arm64 兼容处理**，不是直接启动苹果原厂内核。

主工作树已建立在 `worktrees/UniXNU-renoace`，分支 `codex/renoace-ios26`，21 个子模块已按父提交检出。Reno Ace 的配置独立放在 `device/renoace`。版本及来源见 `sources.lock.json`。

这是一条有源码依据的实验路线，尚未形成 Reno Ace 可启动移植。若目标只考虑尽快在同代芯片上点亮 iOS，`ios-flame` 的 iOS 16.7.16 路径更直接；本轮根据版本偏好将它作为 SM8150 硬件参考，而将 iOS 26 兼容路径作为主线。

## 收集到的主要项目

| 项目 | 项目记录的目标及进展 | 与 Reno Ace 的关系 |
|---|---|---|
| [ios-flame](https://github.com/NWylynko/ios-flame) | Pixel 4，SM8150 / Adreno 640，iOS 16.7.16；README 和补丁包含八核、UFS、GPU/Metal、触控、USB、Wi-Fi，附界面图 | 硬件最接近的直接参考；不是 Reno Ace 已适配版本 |
| [UniXNU-zeta](https://github.com/none24smu/UniXNU-zeta) | Surface Duo 2，SM8350，iOS 26.5.2；包含 arm64e 用户态转换和连续工程记录，后续记录描述进入 Home，仍有黑背景及卡顿 | 本轮 iOS 26 兼容方案来源；SoC、GPU、显示和触控均需改 |
| [UniXNU](https://github.com/UniXNU/UniXNU) | 通用 UEFI/XNU 框架，OS profile、设备仓库和驱动分离；当前主线 arm64e 文档要求原生 PAC | 架构参考；不能因为主线更新就把其硬件前提视为 855 Plus 已具备 |
| [HakiOS](https://github.com/oosexgang/hakios-xnu-kernel) | XNU 8796 系列，POCO X5 Pro / SM7325，维护通用内核、装载器、GPU 等，并提供纯开源 QEMU 测试入口 | 可借鉴后续驱动；不是现成的 SM8150 / iOS 26 路径 |
| [ios-sweet](https://github.com/dipa-studio/ios-sweet) | Redmi Note 10 Pro / SM7150，iOS 16.7.16，多个衍生项目的基础 | 有完整引导、根文件系统、显示与输入的早期实现，芯片距离较远 |
| [ios-topaz](https://github.com/MakrSas/ios-topaz/tree/topaz) | Redmi Note 12 4G / SM6225，iOS 16.7.16，项目新增 GPU、Wi-Fi 等适配 | 可用于跨项目参考；README 部分旧表格与较新的开头描述并未完全同步 |
| [ios-raphael](https://github.com/Gsjsjzhznsz/ios-raphael) | Redmi K20 Pro / SM8150，iOS 16；有锁屏、八核、Goodix 触控记录，README 指向新的 HakiOS fork | 同代平台的辅助参考，但触控不同，旧轮次 USB 曾回退 |
| [UniXNU-guacamole](https://github.com/wochgn/UniXNU-guacamole) | OnePlus 7 Pro / SM8150，Project Aloha UEFI → DarwinBoot → iOS 16 用户态的记录 | UEFI 启动与同代内存配置参考，不能直接使用其板级镜像 |

另检索了 [touchHLE](https://github.com/touchHLE/touchHLE)、[LightTouch](https://github.com/blake-lucas/LightTouch) 和 [Project Sandcastle](https://projectsandcastle.org/)。前两者属于应用兼容或模拟器路线，Sandcastle 是在苹果设备上运行 Android；它们不作为此次原生启动目标的主基线。

第一阶段未发现的 UEFI 资料，现已在第二阶段补齐：[Project Aloha](https://github.com/Project-Aloha/mu_aloha_platforms) 有 `oppo-pclm10` 目标和已发布 NOSB 镜像。它还没有本任务需要的 UniXNU/DarwinBoot 集成，本机也尚未执行该 UEFI；不能由此声称 Reno Ace 的 iOS 已适配。

## iOS 26 的关键问题

Reno Ace 的 `/proc/cpuinfo` 标明 `SM8150_Plus`，八核的 Linux feature 集合没有 `paca` / `pacg`。本轮没有退出 Android 去验证 EL1 的原生 PAC 寄存器，因此准确结论是“当前运行环境没有报告 PAC 能力”。原生 arm64e 路线的条件见 [UniXNU 的 PAC 要求](https://unixnu.com/porting/arm64e)。

`UniXNU-zeta` 的价值在于提供了另一条有实际代码的兼容路径：`rewrite-zeta-userland.py`、`zeta_userland_pauth.py` 和 `rewrite-zeta-dyld-cache.py` 处理普通指针 ABI、可识别的 PAC 指令及 shared cache；内核侧还需要对应的加载、指针修正和接口适配。未知指令形态会被拒绝，不能理解为任何 iOS 26 固件均可转换。

证据分级如下：

- **源码已看到：** 上述转换器、XNU 12377 构建脚本、源版本 pin、设备配置、相关测试都在仓库中。
- **上游 CI 已查到：** [run 40414179387](https://github.com/none24smu/UniXNU-zeta/actions/runs/40414179387) 对设备提交 `cce9be4` 的状态为 `success`。CI 通过不证明 Reno Ace 能启动。
- **上游实机记录：** 调查时的 [zeta README 固定快照](https://github.com/none24smu/UniXNU-zeta/blob/eb489285a1d9153872f00c93ebb519a269b249b5/README.md) 后部描述该配对构建进入 Home，并记录约八分钟的样本，同时明确黑背景和卡顿仍存在。其开头保留较旧的 Stage 6 状态，不能只读开头或只读最后一句。记录中的部分截图和捕获日志路径不在公开仓库，本轮没有独立复现该手机。
- **本机主机测试：** 用已安装 Android NDK 的 Clang 集成汇编器代替测试所需的 `llvm-mc`，执行上游 PAC lowering 的四项测试，全部通过；使用上游断言和 Capstone 解码校验。没有使用或转换实际 IPSW，所以不能据此宣布完整系统兼容。

因此，iOS 26 可以作为研究目标；“缺少 PAC 就完全没有办法”和“只需替换固件即可开机”都不符合目前看到的证据。

## 这台 Reno Ace 的测量结果

| 项目 | 结果 |
|---|---|
| 身份 | OPPO PCLM10，OP4A89，project 19081 |
| CPU / GPU | SM8150 Plus；SoC ID 339、revision 2.2；Adreno640v2 |
| 当前系统 | YAAP Android 15；4.14.352 定制内核；可用 root 只读权限 |
| 内存 | 约 8GB；DT 有三个内存 bank，须扣除 reserved-memory |
| 显示 | Samsung SOFEF03F_M，1080×2400，DSC command mode，60/90Hz timing |
| 触控 | Synaptics S3706，GENI SE17 I²C，`0xc80000` / `0x20` |
| 启动状态 | Android 报告 `orange`；第二阶段实测 fastboot unlocked=yes，但 boot 命令不存在 |
| 镜像布局 | Android boot v2，page size 4096；gzip(Image) 后附 DTB，且另有独立 v2 DTB 区段；两份相同；独立 recovery |
| 启动分区副本 | boot 96MiB、dtbo 24MiB、recovery 96MiB、vbmeta 64KiB；均通过手机/电脑 SHA-256 比对 |

实机触控节点与 [OPPO 官方 19081 DTS](https://github.com/oppo-source/Reno10X-RenoAce-10.0-kernel-source/blob/289d6118ef783a281a8ecf0378e3c560ff6976c4/msm-4.14/arch/arm64/boot/dts/19081/sm8150-mtp.dtsi) 相符；官方仓库还包含 [S3706 驱动](https://github.com/oppo-source/Reno10X-RenoAce-10.0-kernel-source/blob/289d6118ef783a281a8ecf0378e3c560ff6976c4/msm-4.14/drivers/input/touchscreen/oppo_touchscreen/Synaptics/S3706/synaptics_drivers_s3706.c)。已检出相关源码目录，未将该 Android 10 源码当成目前运行内核的逐字节来源。

## 实际落地与边界

已拉取 iOS 26 框架与全部子模块、固定 zeta 参考提交、拉取 flame 及 OPPO 官方板级源码。已保存 live DTB、提取当前 boot 镜像中的 DTB，并生成带来源的硬件参数文件。`renoace_research_defconfig` 能通过 UniXNU 的解析和 source 版本解析。

设备配置沿用上游 `example=true` 标志，明确禁止把尚未完成的资料配置构建成“已适配”镜像。已发现固定分支打包器的 DTB 布局与实机已安装 v2 镜像不同，必须在首个启动探针之前解决。

本轮没有刷写分区、清除用户数据、重启到 fastboot、构建完整 XNU 内核或尝试启动 iOS。启动相关副本不是完整手机备份。下一阶段的具体工作与检查点见 [BRINGUP.md](device/renoace/BRINGUP.md)。
