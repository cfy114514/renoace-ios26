# 第三阶段：P01 实机试验与日志留存

日期：2026-11-06，Asia/Shanghai。本文记录已完成的四轮 P01 试验，并更新第二阶段文档中尚未恢复 ADB、尚未取得 recovery 写入许可的历史状态。手机当前使用已有的 YAAP Android 15。

**四轮均已返回 Android并恢复原 recovery；尚未获得有效的 P01 文本日志，也没有装载或启动 XNU。** P01 是独立的最小 ARM64 引导探针，不是 iOS 或 XNU 内核。

## 电脑连接与 recovery 控制路径

Windows 管理员 UAC 操作已完成。`tools/fix_renoace_adb_guid.ps1` 为当前 Qualcomm ADB Interface 使用的 Microsoft WinUSB 注册补入标准 ADB 接口 GUID，保留旧值备份，然后重启对应设备。`out/bootchain/adb-guid-result.json` 记录 `Success=true`、`Restore=false`；随后实际 ADB 与 root 读取恢复可用。本轮没有以替换所有 USB 驱动作为修复手段。原值备份位于忽略目录中，包含设备实例信息，不写入本文。

开始 P01 前，先实际进入并退出原有 **TWRP 3.7.0_12-RenoAce_by-Art_Chen**，确认 recovery 中有 root ADB，能够返回 YAAP Android并恢复连接。记录位于首轮会话的 `recovery-baseline-info.txt`、`recovery-baseline-hash.txt` 和相关返回记录。

用户已明确授权在本轮 P01 诊断中临时写入独立 recovery、进行测试并恢复原镜像。**同一已授权范围内的试验和复原不需要再次请求同一项许可。** 这不把 boot、ABL/XBL、GPT 或用户数据的改动纳入授权范围。重启与管理员操作仍遵循已确认的用户在场、事先告知安排。

## 实机结果

时间均为主机观察到的模式变化间隔，不等同于探针自身运行时长。每轮开始前均确认设备身份、镜像和分区大小，写入后读取 recovery 的 SHA-256，与本轮目标文件比对，再启动测试。

| 轮次 | 镜像与复位方式 | 返回 fastboot | 返回 Android后的 pstore | 私有会话目录 |
|---|---|---:|---|---|
| 1 | 原 P01，3秒延时后 PSCI，哈希 `b1fe1705…` | 10.735秒 | 空，未找到 P01 标记 | `local-device/p01-test-20261106T131036Z/` |
| 2 | 同一原 P01，重复控制 | 10.825秒 | 空，未找到 P01 标记 | `local-device/p01-repeat-20261106T134001Z/` |
| 3 | P01 direct，改为直接 PS_HOLD 复位，哈希 `4fb033b9…` | 17.182秒 | 导出 `console-ramoops-0`，179,412字节；文本损坏，无 P01 标记 | `local-device/p01-direct-20261106T140738Z/` |
| 4 | PSCI，8秒延时，哈希 `bb3e0d92…` | 14.895秒 | 空，未找到 P01 标记 | `local-device/p01-delay8000-20261106T142802Z/` |

四个会话均观察到测试启动后的 fastboot 枚举，随后使用 `fastboot continue` 返回 YAAP Android，再从 Android/root 路径复原 recovery。仅凭返回 fastboot及其耗时，还不能排除固件回退等其他路径，也不能声称已经读到了探针的 CPU 寄存器。

对应产物：

- 原 P01：`out/renoace-p01/recovery.img`，SHA-256 `b1fe1705799b1b2e2133393237c30bf9555280469efc17740b2b19a0d88106c3`。
- direct 变体：`out/renoace-p01-direct/recovery.img`，SHA-256 `4fb033b9d49e9494b53244938184a9d3f2dfdf1462af7c0ad6b9dd4ffed617ea`。
- 原 recovery：`local-device/20261106T115059Z/recovery.img`，SHA-256 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`。

**每轮结束均恢复并校验到同一原 recovery 哈希 `8c951baa…`。** 四个会话的 `state.json` 还记录 boot、dtbo、vbmeta 的哈希未变化，以及为本轮上传的临时手机文件已移除。没有用其他启动分区替代 recovery。本文不把这些特定分区的核对扩大成对整机每个分区的逐字节证明。

## 写入和日志传输的校验方法

曾观察到 `adb exec-in` 流式写入的主机完成状态不足以可靠确认设备端写入已经结束，后续读取/恢复存在完成时序不确定。没有据此认定具体是 ADB、shell、USB 驱动或其他组件的缺陷。

后续实际流程改为：先把镜像上传到手机临时目录，核对暂存文件哈希；再通过有完成返回的 `adb shell` 执行设备本地 `dd ... conv=fsync`；最后重新读取目标分区哈希。只有目标分区与候选镜像完全一致才开始启动。该流程确认了四轮试验写入的实际镜像身份，并用于恢复后的校验。

第三轮 console 的原始文件 SHA-256 为 `cad7f826b8fdefa44e9ec40c14126c0a71540de3686e996981e60eb571787163`。再次以 base64 取得的精确字节与设备侧哈希核对后，保存为同会话下 `console-ramoops-0.sha256-verified`，与179,412字节原始文件完全相同。

另一份文本模式读取的 `.verified` 文件为180,551字节。它恰好把原文件的1,139个 LF 各扩展成 CRLF，因此那个哈希差异已经解释清楚；不能把它当作再次读取时出现了新的内存损坏。原始文件中的异常字符在精确字节版本中仍然存在。

## 日志损坏的证据与界限

实际绑定的 ramoops 基址为 `0xb7e00000`，总大小 `0x400000`；record、console、ftrace 各 `0x40000`，pmsg `0x200000`，device-info `0x1000`，ECC=0。

匹配运行版本和 local-version 的 Art-Chen aosp-15 源码 `09ec6066c482a93cc65df7860faad3409e9ebe7a` 把 dmesg 放在最前，device-info 放在最后；尚未完成该源码对当前内核的逐字节复现。按该代码计算，五个 dump zone 各为 `0x4c998`，console 从 `0xb7f7eff8` 开始；第一条 dmesg 仍从 `0xb7e00000` 开始。没有发现支持把 P01 记录移动4KiB、改变 magic、或因 `bootmode=recovery` 跳过 pstore 读取的源码依据。原 Android kernel/dtbo 未变化也不支持直接假设生产者与读取者使用了不同布局。

第三轮 Android早期日志出现 `persistent_ram: found existing invalid buffer, size 389, start 449`。这表明某个保留区头通过了 magic 判断，但 start>size，被读取端判为无效；该消息不带地址，不能确定就是 P01 的第一条记录。direct 变体在模拟器成功路径中的预期值为409/409；观察值与它相近，但这不是对实机记录身份的证明。

损坏 console 中可识别出以前的 Android init/service、充电等日志。与先前干净 Android日志中的一个固定136字节消息体比较，某处有112字节相同，其余24字节各差一个 bit。其他位置也呈现独立的 bit 变化，而不是单纯的开头偏移或环形缓冲旋转。**几何错误本身不能解释这种同一消息内部的逐字节 bit 变化。** 但这些近似匹配不能用作整个缓冲区的误码率，更不能据此认定硬件 DRAM 已损坏；复位留存、固件处理和内核处理中的具体原因仍未定位。

标准 Android15 BootReceiver 给 `SYSTEM_LAST_KMSG` 读取的是 console-ramoops 与 `/proc/last_kmsg`，不是 P01 写入的 `dmesg-ramoops-0`。没有该 DropBox 条目不能独立说明 P01 记录何时丢失。检查过的 pstore 源码没有 recovery boot-reason 门控；vendor 初始化清的是 console 工作区，不是 dump0。普通读取不删除记录，显式 unlink 可以清除记录，但本轮没有建立任何实际删除者的证据。

详细源码位置和限定条件见 `out/analysis/p01-pstore-layout-diagnosis.md`、`p01-console-retention-analysis.md`、`p01-console-bit-patterns.json`。原始日志、设备实例信息、镜像、文件副本等全部留在已忽略的 `local-device/`、`out/` 中；本文仅保存必要的结果与哈希。

## 离线验证与实机结果分别代表什么

原 P01 的实际编译 Image 通过17项 Unicorn 指令级测试；direct 变体通过18项。报告分别在 `out/probe-tests/` 与 `out/probe-tests-direct/`。测试覆盖受测的 FDT、记录、SPMI 失败和复位分支；计时器、CPU system registers、SPMI、PSCI/PS_HOLD 是模型，不能证明真实硬件的寄存器行为、复位路径和 RAM 留存。

`build.json` 中的“未实机测试”是生成产物时的快照；已经发生的手机试验以本文和各会话的 `state.json` 为准。所有结论都须绑定具体哈希，不能把一个变体的模拟或实机结果转给另一份镜像。

本阶段只运行 P01 诊断试验。已有 XNU 候选和控制数据仍是离线准备，**没有 XNU 实机入口、内核启动日志或 iOS26 开机结果**。

## 8秒 PSCI 延时对照与下一条日志路径

第四轮镜像为 `out/renoace-p01-psci-8000/recovery.img`，SHA-256 `bb3e0d9269bba2e6d314fd67027c6ca286533eb7c4c25778b5ee60bd59a11d42`。EL1、EL2 和 PSCI 返回后备路径的指令检查通过，模型确认实际等待至少8秒。实机从请求启动到 fastboot 为14.895秒，原 recovery 随后恢复并校验，临时手机文件已删除。

前三秒 PSCI 对照使用约2秒轮询，第四轮使用约0.25秒轮询，包含进程启动开销；两个观察值不能当作精确的内核耗时。约4秒的观察差与预期多等待5秒相符，支持代码到达等待阶段，但仍不是寄存器日志或 XNU 启动证明。八秒构建还包含后来增加的异常重入停止保护，因此不是仅修改一个二进制字节的严格实验。

继续扩大 PMIC/复位设置没有足够依据。下一条候选路径是在当前 Android Linux Image 的尾部放置诊断 stub，记录到克隆的运行时 FDT `/chosen/renoace-probe-log`，恢复原入口和 Image header 后直接继续原 Android 内核；避开复位留存。该路径须先完成原镜像逐字节校验、运行时内存/DTB/initrd 冲突检查、缓存交接和指令测试，尚未在手机运行。原始 Android 内核在先前 `/proc/iomem` 中位于 `0xa8880000` 起，不能把模拟器的 `0x80080000` 写死为实机地址。
