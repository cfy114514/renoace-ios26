# 第十一阶段：P08 原始设备映射与 USB 时钟只读快照

2026-11-07。P07 已在实机完成 VM 初始化和恢复。P08 继续验证原始 XNU 的 `ml_io_map`、Device 内存属性及八个 GCC 电源/时钟状态的读取。**P08 已在实机通过：原始设备映射、496页 Device 属性、八次只读快照及状态恢复均验证成功；原 recovery 已恢复，正常 YAAP 与清理核验通过。尚未启用 USB 控制器或 DMA，也没有 XNU 运行期电脑交互证明。**

## 冻结候选与执行范围

构建 `6c44af6950b61ed2`，Image SHA-256 `50fa9472f040f99c3b96b47ee1f9b21f6e84cc7a3a2ed1239edb97f78b580167`；原始内核仍为正式零基址修复产物 `c361eda7d383619ec76c814a4f2121955547fadaa8235131d6849aa14d995743`。936字节 RX 入口位于相同已核验填充区，SHA-256 `efc46cf7524408bf065873cecc1c474d5b620aa007427f8b8bc7ffe0ad0f05dc`；272个观测补丁包括38个控制字与234个入口字，原始内核文件和 initrd 成员不变。

停止在完整原始 `arm_vm_init` 返回处，调用原始 `_ml_io_map` (`0xfffffff007508144`)。该包装器传递 `VM_WIMG_IO=7`、读写保护3和不可取消映射参数0，原始 `_io_map` 当前使用 pre-KMEM 路径：推进 `virtual_space_start`，由原始 `pmap_map_bd` 建表，不依赖尚未初始化的 `kernel_map`。

映射 GCC 物理范围 `[0x100000,0x2f0000)`，共496页。原始页表使用 AttrIndx3，对应 MAIR 字节`0x00`，即 Device-nGnRnE，且 PXN/UXN。门控用真实 AT/PAR 检查首个物理页和 Device 属性，C 返回后再独立有界遍历全部496页。映射是 CPU 设备映射，不建立 USB DMA/IOVA，也不配置 SMMU。

原始 pmap 代码使用 SIMD。入口在已核验的 XNU 栈上保存32个 Q 寄存器、FPCR/FPSR、PAR及检查点所需 GPR，借用`0x240`字节；调用返回后恢复。异常入口跳过 I/O 再入，直接使用既有原调用方上下文恢复栈和 FP。异常中保留的深层 SP/部分读取计数属于故障证据，不能报成正常快照完成。

## 只读白名单与本机差异

所有数值来自本机捕获的 DT 与固定 OPPO19081 源码交叉核验，当前不写任何寄存器。

| GCC 偏移 | 物理地址 | 名称 |
|---|---|---|
| `0xf004` | `0x10f004` | USB30_PRIM GDSCR |
| `0xf010` | `0x10f010` | USB30_PRIM master CBCR |
| `0xf014` | `0x10f014` | USB30_PRIM sleep CBCR |
| `0xf018` | `0x10f018` | USB30_PRIM UTMI CBCR |
| `0xf078` | `0x10f078` | USB_PRIM configuration NoC CBCR |
| `0xf07c` | `0x10f07c` | USB_PRIM aggregate AXI CBCR |
| `0xf050` | `0x10f050` | USB3_PRIM PHY auxiliary CBCR |
| `0x8c028` | `0x18c028` | USB3_SEC CLKREF CBCR，本机 USB0 的实际 xo 依赖 |

Reno Ace 的 USB0 使用 SEC CLKREF，不能照搬 flame 的 PRIM `+0x8c008`。控制器范围`0x0a600000`、Synopsys femto HS PHY`0x088e2000`和 apps-SMMU/SID`0x140`仍只属于已核验拓扑，P08 不访问这些外设。GCC 的 GDSCR 位31是电源开启状态，CBCR 位31是时钟关闭状态，位0是软件启用请求；单个快照不证明完整 PHY/USB 链路已准备好。

## 验证与集成门控

原型构建器始终拒绝制作 recovery；单独的集成打包器必须重新核对候选源码、原始镜像/CPIO/ADT、272个补丁、三个恢复跳转、ABL几何、严格原始记录、190项当前编译内存原语和两个独立审查。

七个原生模型用例覆盖正向、空映射返回、失效页表后的真实 AT 拒绝、错误栈，以及显式合成的映射内异常、首读前异常和两次读取后的异常。正向没有主机运行时注入，MMU 和原始映射函数均真实执行；GCC 物理寄存器值是明确标注的只读模型夹具，不是手机测量。必须验证全部496个原本为空的目标页、八次32位白名单读取、零外设写入及精确调用方/FP状态恢复。异常投递夹具不冒充原生总线异常。

日志使用 `RENOACE-XNU-IO-P08`、诊断版本4和`io_schema=1`。只有完整原始 VM、正常恢复、正确 I/O magic/status/次数/顺序、VA/VSS/PAR关系和496页遍历同时通过，才置`io_verified=1`及`xnu_status=0`。状态25拒绝不完整或不匹配记录，26拒绝 Device 映射。严格读取器独立检查字段；改变 SEC 偏移、完成状态、计数、页数、PAR 或地址均不能得到快照成功。

源码覆盖：`device/renoace/xnu_io_probe/`；构建器：`tools/build_renoace_io_probe.py`；独立集成器：`tools/package_renoace_io_probe.py`；完整派生源码及输出：`out/xnu-io-probe/compiled-source/`。P07 输入固定哈希且不修改，模型/设备证据分别保留。实机结果和原镜像恢复状态只在实际执行后追加。

## 实机快照与恢复

会话 `local-device/p08-xnu-entry-20261107T001808Z/`。载体 SHA-256 `146f4dffc35d688e9cfb8a9887120f886610d4fefb60a15142db97082fe08021`。原始手机记录6,479字节，SHA-256 `ff61b28d4018e4d1945ae443148f65264828a21e1123e35824e16fc975855ba1`；构建编号、CRC和手机/电脑传输SHA均匹配，严格读取器`xnu_io_verified=true`、失败列表为空。

| 实机项目 | 结果 |
|---|---|
| 原始 I/O 入口 PC / 检查点 SP0 | `0xfffffff007500950` / `0xfffffff007dbff30` |
| GCC Device VA / PA / 长度 | `0xfffffff023400000` / `0x100000` / `0x1f0000` |
| VSS 前 / 后 | `0xfffffff023400000` / `0xfffffff0235f0000` |
| 页数 / 原生 PAR | `496` / `0x100b00`，Device属性与物理页匹配 |
| 启动阶段 / 读取数 / 完成 | `3` / `8` / `io_status=2, io_verified=1` |
| USB30_PRIM GDSCR | `0xf8222000`：电源状态位31为1，软件collapse位0为0 |
| USB30_PRIM master CBCR | `0x4221`：软件请求1，CLK_OFF位31为0 |
| sleep / UTMI / cfg-NoC / aggregate-AXI / PHY-aux / SEC-clkref | 六项均为`0x1`：软件请求1，CLK_OFF为0 |
| VM 最终分配边界 | `0x181902000` |
| 原调用方 / SIMD/FP / CNTKCTL | 均验证恢复；Q CRC均为`0xe0811e85` |

总控制耗时 `2.8217980208333335` 秒，包含装载、校验、原始 VM、设备映射、读取和恢复，不是纯 I/O 时间。上述位解释只属于采样时的电源/时钟观察；没有因此推断 DWC3 访问、PHY、PLL、NoC权限、SMMU/DMA或电脑连接已可用。master的其他位按固定驱动定义分别保留，未解释的位不赋造语义。

本轮正常返回后，原 recovery 已恢复并读回 SHA-256 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`；boot/dtbo/vbmeta 哈希匹配原值。最终`boot_completed=1`，诊断属性与暂存目录均不存在。没有外设写入、USB复位、端点启动、DMA、SMMU或PHY编程。

精确构建、完整派生源码、模型/独立证据和手机结果冻结在`out/xnu-io-probe-attempt1/`：114文件共289,005,518字节，复制和哈希核对通过，历史partial原型被排除。下一步先核对core-reset，再评估受条件约束的单页DWC3身份/状态读取；当前仍不进行永久实验系统替换。
