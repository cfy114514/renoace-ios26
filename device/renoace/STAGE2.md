# 第二阶段：引导入口、P01 与 XNU 准备

日期：2026-11-06。当前系统是用户已有的 **YAAP Android 15 定制 ROM**，不是 ColorOS。实机来源始终是本机镜像、live DT 和实际运行结果；官方 OPPO 源码仅用于硬件接口交叉核对。

本文是实机写入前的阶段记录。后续 ADB 修复、已授权的 recovery 试验及恢复结果以 [STAGE3.md](STAGE3.md) 为准。

## 已经发生的实机操作

1. 读取并校验 ABL、XBL、persist、modemst1、modemst2、fsg、fsc 的副本，另外确认前一阶段 boot/dtbo/recovery/vbmeta 的 SHA-256 仍与手机一致。副本位置由 `local-device/bootchain-backup-latest.txt` 指向。
2. 从 Android 进入厂商 fastboot，得到 `product=msmnile`、`unlocked=yes`、`secure=yes`、`max-download-size=805306368`（768MiB）。
3. 用当前安装的完整 boot 镜像做控制测试：96MiB 下载成功，`boot` 命令返回 `unknown command`。这是命令入口缺失，不能解释为镜像格式验签失败。
4. `fastboot reboot` 成功。用户随后确认需解锁手机，已解锁并重新插拔；ADB 尚未恢复。Windows 当前枚举为 Qualcomm 90DB 的 ADB Interface / Microsoft WinUSB，但没有 DeviceInterfaceGUIDs，其他诊断接口还有缺失驱动。
5. 已准备一个只补标准 ADB 接口 GUID 的电脑端修复脚本。管理员启动尝试被取消，没有产生修复结果或原值备份文件，未确认任何注册表修改。当前没有待确认 UAC，不再次自动弹出。

没有刷写手机分区，也没有在手机执行 P01、UEFI 或 XNU。Android 重启过程产生的状态变化不等于完成了新内核启动。

## 引导限制的独立核对

对本机 ABL 的离线格式解析和 ARM64 指令检查找到 16 个 fastboot 命令注册项，没有 `boot`，与实测一致。当前 boot 和 recovery 各自嵌入的 IKCONFIG 都未启用 KEXEC、CRASH_DUMP、DEVMEM。普通 `fastboot boot` 和已有内核的 kexec 均不可用。`continue` 只能继续现有启动路径，不能替代临时内核装载。

完整命令表、镜像布局及配置证据在 `out/analysis/early-log-transport.md` 和 `early-log-evidence.json`。REA 本机没有已配置的深度反汇编后端，因此离线检查使用格式解析、LLVM/Capstone；没有把这些结果称作 REA 反编译证据。

## 修正第一阶段的两点结论

- **现成 UEFI 目标存在。** Project Aloha 有 `oppo-pclm10`，源码固定在 `78ff39135c65cbdcf353db277ffeea61f965698e`，已检出到 `references/aloha`。已取得 release `2412.74` 的 NOSB 镜像和 FD，ZIP CRC 及镜像内 FD 的逐字节一致性通过。它会初始化 UFS/厂商 DXE，且尚无本任务需要的 UniXNU/DarwinBoot RAM payload 集成，不能直接视为最小诊断探针。
- **当前镜像有两份 DTB。** boot 和 recovery 都是 `gzip(Image)+DTB`，同时有独立的 v2 DTB 区段；两份均为 506,979 字节且相同。P01 保留两份，不能只保留其中一种布局后宣称与现有镜像一致。

## P01：已构建的最小诊断镜像

源码：`device/renoace/probe/`；构建工具：`tools/build_renoace_probe.py`。
产物：`out/renoace-p01/recovery.img`，96MiB。
当前构建的内容哈希、工具来源、输入哈希和检查记录，以旁边 `build.json` 为准。

它做的事情：检查 EL/MMU 状态和 runtime FDT；只在 DT 确认 ramoops 区域、record 大小和 ECC=0 后，写入保留 RAM 的第一条记录；记录 CPU 特性；按 PM8150 既有接口选择 bootloader 并设置 warm PS_HOLD 类型，读回确认；等待三秒；发出 PSCI reset。若 PSCI 返回，只在板级/复位配置确认后才使用 PS_HOLD 作为后备。没有 UFS、GPU、额外 CPU 或分区写入代码。

若早期条件不符且返回目标尚未确认，探针停留而不是反复重入 recovery。这意味着**首次实机测试仍可能需要人工强制复位**。寄存器读回、DRAM 留存、bootloader 处理及 pstore 文件导出都还没有手机上的证明；自动返回是代码路径，不是已验证的承诺。

打包保留当前 recovery 的 ramdisk、DTBO、两份 DTB、cmdline、OS 字段和装载地址，仅替换 kernel。使用新的 AVB `NONE` 哈希描述，未复用原镜像的失效签名；离线哈希验证通过不等于 ABL 必然接受。源码和打包器没有调用 ADB/fastboot。

本机检查已通过：无未解析符号、C 对象无绝对地址重定位、Linux Image 头、gzip/DTB 回解、原始分区 SHA-256、Android 镜像 ID、各保留区段逐字节比对、AVB footer 和 hash descriptor。旧 AOSP v2 打包器的一处 Python2 整数除法，在输出目录的临时副本中做了明确的 Python3 修正，原下载源码未改。

ARM64 指令测试由 `tools/test_renoace_probe.py` 执行，报告在 `out/probe-tests/`。对实际编译的 Image 共17项通过，包括 EL1/EL2、有效记录、PSCI 返回后的 PS_HOLD 后备、异常 FDT/ECC、SPMI 超时/错误/所有权和读回失败。没有观察到受测路径上的非预期内存或 MMIO 写入。测试中的 CPU 寄存器、SPMI、定时器和 PSCI 是模型；这些结果不能代替手机测试，也不证明 RAM 跨复位保留。

## XNU 已准备的内容

- 已保存公开 CI 的普通 ARM64、未 prelink XNU 12377.121.6 / Darwin25.5.0 候选：`out/analysis/xnu-candidate/extracted/zeta/kernel/mach.development.bcm2837.unstripped.noctf`。来源 run `41135403689`、提交 `7f981f88`，ZIP digest 和内核哈希已核对。
- 该产物的配置名虽然带 iOS27，其实际 XNU source pin 仍是 12377.121.6；后续用户态兼容选项与本任务 a8b90c0 基线不同。它只准备作为早期 entry/MMU/arm_init 控制，不能冒充匹配的完整 iOS26 镜像。
- `device/renoace/drivers/ArmCpu` 是独立设备覆盖：把定时器启用和中断分派统一为实机 DT 的 INTID19。上游五个 XNU12377 补丁全部可按原顺序应用，UniXNU 能正确解析到设备覆盖。**尚未进行完整内核编译和 IRQ 实测；已下载的候选仍保留原 INTID27。**
- 静态核对表明，候选 UFS 驱动在 `native-ufs-probe=0 native-ufs-root=0` 时会在 MMIO 前返回；初次控制还应省略 USB console、RAMDisk、pram 等节点，并在 CPU 驱动初始化前停止。不能原样复用 zeta 的硬件探针和 RAM 地址。
- 已新增 `tools/prepare_renoace_xnu_control.py`，生成 `out/xnu-control/load-plan.json`、最小 ADT 和1152字节 boot_args；10项校验全部通过，包括 LLVM/ctypes/上游 ADT 解析器交叉核对和损坏输入拒绝。候选窗口为 `0x180004000 + 0x10000000`，只通过实测 DT 的保留区排除检查，尚未确认运行时所有权。产物明确 `ready_for_boot=false`、`handoff_permitted=false`：没有内核修改、停止跳板、引导装载器或可刷镜像，不能直接把控制数据当成可以执行的启动包。

## 等用户在电脑旁后才能继续的实机步骤

1. 恢复 ADB，并确认当前 YAAP、root、分区大小及副本哈希。优先核对电脑端修复结果，不重复盲目拔插。
2. 每次重启前明确通知用户，给用户拿到手机的机会；重启后等待解锁和 ADB 恢复。用户不在电脑旁时不再次发起 UAC，也不开始新的试验启动。
3. 先验证当前 recovery 的进入和退出路径。然后对明确的 P01 文件、只覆盖 `recovery`、复原旧镜像的计划取得许可。当前“继续推进/离线工作”不作为覆写分区的许可。
4. 如获许可，临时写入 P01 到独立 recovery，启动一次，观察是否按设计返回；随后恢复原 recovery，并通过 SHA-256 确认恢复。实际操作时不能把 `boot`、ABL/XBL、GPT 或 userdata 当作 recovery 的替代目标。
5. 返回 Android、解锁后读取 pstore。只有获得带 `RENOACE-P01` 的有效实机记录，才建立该日志通道的证明，再进行 XNU 入口探针。没有记录时应报告“留存未证实”，不能推断 XNU 已执行或未执行。

原 recovery：`local-device/20261106T115059Z/recovery.img`，SHA-256 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`。这套复原方案仍依赖至少一个可达的 Android/fastboot 入口；首次运行需要用户在场。
