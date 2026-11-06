# 第五阶段：P03 已验证七条 XNU 原始入口指令并返回

2026-11-07，Asia/Shanghai。**第二次 P03 已在 Reno Ace 上通过受控 XNU 入口验证：装载和校验完成，执行七条原始入口指令，经私有返回点回到诊断桥，再继续原 Linux。** 实机记录通过构建身份、CRC32、传输 SHA-256 和前后状态检查。原 recovery 已恢复并核对，最终确认原有 YAAP Android正常启动。

这是有限入口检查点，尚不代表完整 XNU 内核启动、MMU/中断初始化或 iOS26 用户态开机。第一次5秒预算拒绝保留为控制结果；第二次成功使用另一构建和独立会话，不能互相替代证据。

| 尝试 | 构建编号 | 实机结果 | 控制耗时 |
|---|---|---|---:|
| 1 | `3f48abe7fab0c59f` | 预算拒绝，attempted=0、returned=0 | 约5.000169秒 / 5秒预算 |
| 2 | `5b983b87fd3358b8` | 有限入口返回通过，attempted=1、returned=1 | 约5.734170秒 / 15秒预算 |

## 第一次：身份与历史副本

- 构建编号：`3f48abe7fab0c59f`。
- 实机 recovery 镜像 SHA-256：`a69db62ea4a3107865cf7034a5fd427bed804586cd1e37a9f18f795f35ef14fd`；写入后的分区读回哈希一致。
- 编译后 Image SHA-256：`e45dd2487834b1d9780a210dd1f5db31b3232602e38f83359e2cfbe8574479bf`。
- 实机会话：`local-device/p03-xnu-entry-20261106T171305Z/`；目录时间为 UTC，对应本地11月7日凌晨。
- 原始 FDT 记录：会话下 `entry-log/probe-log.bin`，1,369字节，SHA-256 `05199c538e970d265d255651aee13d524102732bbbd5d38d2b042e279c29bd20`。构建身份、字段结构、CRC32 和手机/主机传输 SHA-256 均已验证。

在优化下一版前，已经把**第一次构建的完整输出**保存在 `out/xnu-entry-probe-attempt1/`：包含 Image、recovery.img、压缩载荷、ELF/对象、布局、模型记录、指令测试及读取器报告。该目录的 `source-snapshot/` 另保存对应设备源码、测试源码、构建器、读取器和打包辅助脚本。

`snapshot-manifest.json` 记录36个文件、282,631,071字节；每个文件均检查复制前源哈希、目标哈希及复制后源哈希。编译源码和测试源码的哈希与第一次构建/测试报告一致。读取器副本包含试验后新增的 `xnu_status_name`、`xnu_elapsed_seconds` 展示字段，未改变输入记录格式；不把该读取器副本称作试验前的完全相同修订。

后续可重新生成 `out/xnu-entry-probe/`，但不能用新文件解释这次运行。第一次结果应始终对照上述历史副本和原始会话。原始镜像、源码快照中的本机路径和设备日志均留在已忽略的 `out/`、`local-device/` 中。

## 第一次：预算拒绝记录

| 字段 | 手机返回值 | 可支持的结论 |
|---|---|---|
| `xnu_status` | `0x7` | 对应此版源码的预算拒绝路径 |
| `xnu_attempted` | `0` | 尚未执行进入 XNU 的调用 |
| `xnu_returned` | `0` | 没有 XNU 返回事件 |
| `xnu_window_used` | `1` | 装载控制已开始使用目标内存窗口 |
| `xnu_phys_base` | `0x180004000` | 本次目标物理起点 |
| `xnu_window_size` | `0x10000000` | 本次配置的窗口大小 |
| `xnu_copied` | `0xc60000` | 装载器报告累计12,976,128字节，12.375MiB |
| `xnu_zeroed` | `0` | 尚无完成的清零字节计数 |
| `xnu_elapsed_ticks` | `0x5b8e4b2`，96,003,250 ticks | 以实机频率换算约5.000169秒 |
| `cntfrq` | `0x124f800`，19,200,000Hz | 上述换算的实机计时基准 |
| `xnu_args` / `xnu_entry` / `xnu_gate` | 均为0 | 尚未进入后续交接准备完成状态 |

读取器把 `record_verified` 判为 true，同时把 `xnu_entry_verified` 判为 false；两者含义不同。前者证明取回的记录可信，后者明确拒绝把这次结果算作 XNU 入口成功。

复制计数不代表整份内核已经装入，也不代表每个目标段的 CRC 检查全部完成。该版多个有界循环共享同一预算，首次记录没有足够的分阶段计时来精确定位哪一个循环耗尽了预算；不能仅凭总耗时断言是特定复制函数、校验函数或硬件故障。

桥接本身记录的 Image 地址为 `0xa8880000`、原 FDT 为 `0xaed7e000`、带日志 FDT 为 `0xac090000`、initrd 为 `0xaef7f000..0xb07fef94`。CPU 仍从 EL1 进入，CNTFRQ 与上一阶段一致。这些是本次原始记录中的实机值，不是模型常量。

## 第一次：返回与恢复

主机在发起本次启动后约44.942秒重新观察到 ADB device。这个间隔包括固件及 Android 启动，不能当成 XNU 执行时间。

取回记录后，原 recovery 已写回并读回核对：

`8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`

boot、dtbo、vbmeta 的哈希与测试前一致；手机上的试验暂存文件已清理。`state.json` 记录 `restore_required=false`、`original_recovery_restored=true`。

恢复后，一次未指定目标的 `adb reboot` 意外进入了**已恢复的原 TWRP**。用户询问是否应重启系统；确认 ADB 当前处于 recovery 后，执行了明确的 `adb reboot system`。最终 `final-normal-boot.txt` 验证：YAAP `sys.boot_completed=1`、原 recovery 哈希正确、诊断 FDT 属性不存在、试验暂存文件不存在。未据此认定普通重启进入 TWRP 的底层原因已查清。

## 第二次：实机有限入口成功

第二次构建优化了装载/校验路径，增加分阶段计时，并使用15秒总预算。其身份如下：

- 构建编号：`5b983b87fd3358b8`。
- recovery 载体 SHA-256：`8956af749d280ecdb67feadbadd6ce4ef1841800b0dbf1db9496d08d882d14f6`；会话的 `operations.txt` 记录写入后的分区读回哈希一致。
- 编译后 Image SHA-256：`d3dacf893b0ce9f843779ccbf2f19d247b90d90af5fc8d4e3d1c6e39d62ef451`。
- 固定 XNU 输入 SHA-256：`c973fe6cf1f039781972b580a9423613effd08806e66bd88ac5a2d2a9e3ef0fb`。原始输入文件未修改；只在装载到 RAM 的私有副本中把预定 gate 改为 RET，以便有限入口执行后返回。
- 实机会话：`local-device/p03-xnu-entry-20261106T180230Z/`。
- 实机记录：会话下 `entry-log/probe-log.bin`，1,791字节，SHA-256 `be81d5fad5e142e27bb8f24630bb225f086393a026a33eaa3dc0228da9d2d279`。
- 第二次构建及对应源码/测试/读取器历史副本：`out/xnu-entry-probe-attempt2/`。`snapshot-manifest.json` 记录48个文件、282,869,134字节；源文件复制前后和目标文件哈希一致，编译源码/测试源码与报告匹配。

本轮原始记录与读取器结果明确为 `record_verified=true`、`xnu_entry_verified=true`、`xnu_verification_failures=[]`。完整10个 Mach-O 段按固定布局装载；输入及目标段 CRC、应清零区域检查均通过，随后才进入受控入口。

| 字段 | 实机返回值 |
|---|---|
| 状态 | `xnu_status=0`，`entry_return_verified` |
| 调用与返回 | `xnu_attempted=1`，`xnu_returned=1` |
| 复制总量 | `0x170a0b8`，24,158,392字节 |
| 段清零计数（BSS等） | `0x73bdf48`，121,364,296字节 |
| 总计时 | `0x68feebe`，110,096,062 ticks；约5.734169896秒 |
| 配置预算 | `0x3a98`，15,000毫秒 |
| XNU 入口 | `0x18053c518` |
| 私有返回 gate | `0x18053e098` |
| 参数地址 | `0x188acc000` |
| 返回捕获 x0 | `0x18053d000`，与预期向量地址一致 |
| 返回捕获 x20 | `0x188acc000`，与传入参数地址一致 |
| 返回捕获 x21 | `0` |

SP、VBAR、SCTLR、NZCV、DAIF 的前后捕获一致，OSLSR 前后均为 `0x8`。这些状态、固定入口字节/返回 gate 与记录中的调用标志共同支持预设七条原始指令的有限执行验证；不是仅因为文件被复制或模型曾经通过就判定成功。

本轮分阶段计时直接来自手机：

| 阶段 | 秒 |
|---|---:|
| 输入 CRC | 1.014908 |
| 缓存维护 | 0.013508 |
| 复制 | 0.858721 |
| 清零 | 0.157001 |
| 目标 CRC 核对 | 1.025784 |
| 清零核对 | 2.664108 |

总计时还包括少量其他控制开销。`entry_call` 阶段记录232 ticks，约12微秒，其中包含包装器与记账操作，**不能当作七条 XNU 指令自身的速度测量**。主机约47.085秒观察到 ADB device，该间隔还包括固件和 Linux/Android 启动，也不能与5.734秒装载计时混为一谈。

## 第二次：恢复与最终正常启动

记录取回后，原 recovery 已恢复并再次读回 SHA-256 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`。boot、dtbo、vbmeta 哈希未变化，试验暂存文件已清除。

这次在载体回交的 YAAP 中执行明确的 `adb reboot system`，仍然进入了**已恢复的原 TWRP**；识别当前 recovery 后，又从 TWRP 执行一次 `adb reboot system`，随后才确认原 YAAP `boot_completed=1`。最终核对原 recovery 哈希正确、诊断 FDT 属性不存在、试验暂存文件不存在。会话状态记录 `final_original_android_boot_verified=true`。本轮经两次明确的 system 重启才回到 YAAP，尚未查明进入 TWRP 的原因。

## 实机证据与后续边界

第一次构建的模型成功路径没有预测实机装载速度，实际先出现预算拒绝；第二次才取得真正的入口成功记录。第二次对应的九项指令模型用例仍只是辅助验证，不能代替本轮手机证据。构建报告中的“hardware-untested”是构建时快照；历史实机结论以各自哈希、原始记录和会话状态为准。

**已经证明的是固定 XNU 副本的有限入口执行与返回。** 完整内核初始化、真正启用 XNU 自己的后续异常/地址转换路径、驱动启动及 iOS26 用户态仍未完成。推进更深检查点时应继续保留这次可返回的成功构建，逐个记录新的入口范围、日志和复原结果。
