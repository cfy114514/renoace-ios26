# 第四阶段：P02 实机日志桥接成功

2026-11-06。P02 在恢复分区中作为诊断载体启动，随后直接继续运行用户原有 YAAP Android 15 内核。**已取得带构建身份、CRC32 和传输 SHA-256 验证的真实启动记录；尚未启动 XNU。**

## 绑定的源码、镜像与证据

- 构建编号：`897f37d63f898a20`。
- recovery 载体：`out/chainprobe/recovery.img`，SHA-256 `2a4a9e22b95fd9c97f4f98bf2cdcfb3b74b36780b8de415047912a571678d9e1`。
- 实机会话：`local-device/p02-chain-20261106T152335Z/`。
- 原始记录：该会话的 `chain-log/probe-log.bin`，423字节，SHA-256 `f73bf2462fc7f93c51047228d950a13af03a9af4b89b442f4c75039aa818edcf`。
- 读取器：`tools/capture_renoace_chainprobe.py`。base64 传输后的字节与手机端 SHA-256 一致；记录的 magic、构建编号、所有字段及 CRC32 均通过。
- 在手机执行前，实际编译指令通过16项模型用例，且用模型产生的真实记录对读取器做了交叉验证；篡改字节和错误构建编号会被拒绝。

## 实机记录

| 字段 | 值 |
|---|---|
| Image 加载地址 | `0xa8880000` |
| 原始运行时 FDT | `0xb0488000` |
| 带日志的 FDT | `0xac080000` |
| initrd | `0xb0689000..0xb07fedd7` |
| CurrentEL | `1` |
| MIDR | `0x51df805e` |
| MPIDR | `0x81000000` |
| ID_AA64ISAR0_EL1 | `0x100010211120` |
| ID_AA64ISAR1_EL1 | `0x100001` |
| ID_AA64MMFR0_EL1 | `0x101122` |
| ID_AA64MMFR1_EL1 | `0x10212122` |
| CNTFRQ | `0x124f800`，19,200,000Hz |

这些数值来自实机 FDT 记录，不是模拟器的 CPU 模型。它们确认了当前启动 CPU 的 EL1 入口及普通 arm64 路线的硬件依据。ISAR1 的 APA/API/GPA/GPI 字段均为0：该启动 CPU 没有报告 PAC 功能；本轮未逐核采样其他七核。

## 日志路径和内存边界

P02 在当前 Linux Image 的尾部加入诊断代码，临时重定向首条分支，采集信息并克隆运行时 FDT，加入 `/chosen/renoace-probe-log`。它恢复原 Linux 入口指令和 image_size，再继续 Linux；没有经过 P01 的复位后 RAM 留存路径。

主机约38.645秒观察到 ADB authorizing，40.777秒观察到 device；随后正常读取 YAAP 和 root。返回路径、日志 CRC 与构建身份共同提供了本机执行和原内核回交的证据。

此前扩大 Image 的入场边界疑问已用本机 ABL 指令核对：gzip 输出有 `DTBLoad−KernelLoad` 容量限制，image_size 也在交接前检查，输入 DTB/initrd 不仅由探针的晚期 C 检查保护。完整 EFI 排他内存图没有单独取得；不要把此次成功扩大成任意尾部地址、任意固件或任意 Image 都可安全使用的结论。后续应继续固定当前实际地址、代码与输入身份。

## 恢复结果

记录保存后，原 recovery 已恢复并读回 SHA-256：

`8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`

boot、dtbo、vbmeta 的哈希仍与测试前一致；手机临时镜像文件已删除，当前系统为 YAAP。会话中 `restore_required=false`、`original_recovery_restored=true`。

## 与 XNU 目标的界限

本轮诊断 stub 和返回的操作系统都是独立探针/原 Android Linux；**这些结果不是 XNU 内核启动证明，更不是 iOS26 开机。** 下一检查点是装载受控 XNU 副本，验证最早入口指令，并通过这条已验证的 FDT 通道返回结果。未验证的完整内核、MMU/中断初始化和 iOS 用户态仍需分别推进。
