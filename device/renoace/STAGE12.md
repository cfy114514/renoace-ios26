# 第十二阶段：P09 实机 DWC3.1 条件只读识别

2026-11-07。**P09 已在 Reno Ace 上通过：原始 XNU VM/设备映射、GCC/core-reset 条件检查、DWC3.1 身份和状态读取，以及完整状态恢复均验证成功。原 recovery 已恢复并正常回到 YAAP。** 控制器尚未启动传输；没有 USB 枚举、DMA/IOVA 或 XNU 运行期电脑交互证明，完整 iOS 尚未开机。

## 身份与实机证据

- 构建 `e7a8d562e64fdf04`，Image SHA-256 `83d1aa88717a66c698222e02fdde79fca59f32e039a6cc78a75fcabe04f5fcd8`。
- recovery 载体 SHA-256 `57bc8c0d7b45519e816f33ae6d49ae22ffeca6a4134167e42f0c65031c45f158`。
- 内核仍为正式零基址修复产物 `c361eda7d383619ec76c814a4f2121955547fadaa8235131d6849aa14d995743`。
- 会话 `local-device/p09-xnu-entry-20261107T003520Z/`；原始记录7,053字节，SHA-256 `331e658047441437e9ca5f33376a7a6d632c783dcf383f3c53b2a9a4820c0e7d`。
- 构建编号、CRC及手机/电脑传输SHA均匹配，严格读取器 `xnu_usb_inventory_verified=true`，失败列表为空。
- 总控制耗时 `2.8181288541666665` 秒，包含装载、校验、原始 VM、两次原始设备映射、读取和恢复，并非纯 USB 时间。

## 条件与只读范围

P08 的八项 GCC 快照保留。先读取 GCC core BCR `+0xf000`，要求复位位0清除、电源域开启且本地collapse清除，六路 wrapper 时钟有本地请求且未报告停止。PHY辅助时钟保留为诊断信息，不把它当作所有 USB2 CPU访问的必需条件。

通过原始 `_ml_io_map` 再映射一页 PA `0x0a60c000/0x1000`，验证 Device-nGnRnE、特权权限和 PXN/UXN。该页末尾有`0x300`字节位于 DT 核心范围之外，但实际五个访问均在核心声明范围内；未访问映射页的其余地址。映射之后重新读取八项 GCC 和 BCR，要求九值与之前完全一致，才读取控制器。

读取顺序是 GSNPSID(`core+0xc120`)、GHWPARAMS0(`+0xc140`)、GCTL(`+0xc110`)，仅在识别ID、gadget/DRD能力、device角色和core-reset状态匹配时读取DCTL(`+0xc704`)，DCTL复位清除后才读DSTS(`+0xc70c`)。没有事件/FIFO读取、寄存器写入、控制器复位、端点配置、PHY/SMMU或DMA操作。电源/时钟的重复观测仍不是永久持有权限或完整硬件就绪证明。

实机新页 VA `0xfffffff037bf0000`、PA `0x0a60c000`、原生 PAR `0x0a60cb00`；C独立页表遍历通过。GCC496页也保留通过，`usb_bcr=0`、`usb_coherent=1`、`usb_status=2`、`usb_count=5`、`usb_page_verified=1`。

| 寄存器 | 实测值 | 固定 OPPO 源码支持的解释 |
|---|---|---|
| GSNPSID | `0x33313130` | 上16位`0x3331`识别 DWC_usb31 / DWC3.1 IP 系列 |
| GHWPARAMS0 | `0x4020400a` | 模式能力位1:0为2，即DRD双角色能力 |
| GCTL | `0x00102000` | 配置角色位13:12为2，即device；core soft reset位11为0 |
| DCTL | `0x00f00000` | RUN_STOP位31为0，CSFTRST位30为0 |
| DSTS | `0x00420004` | DEVCTRLHLT位22为1，RXFIFOEMPTY位17为1 |

该快照报告控制器halt状态。不能用DSTS中残留的速度/链路编码推断已连接主机、协商速度或枚举成功。`0x3331`分支的精确版本需要另读VER_NUMBER/VER_TYPE；本轮没有采样，不能直接把GSNPSID低16位当作版本。CPU Device映射和状态访问也不能证明设备DMA能访问RAM。

## 验证、返回与冻结

1504字节 RX 入口位于原有2KiB填充区，共414个观测补丁（38控制字、376入口字）和三个独立桥内恢复分支。4KiB上下文中的新增记录位于`0xd40..0xdc0`，没有覆盖原 Q/FP/CNTKCTL 保存区。继承的`0x240`借用栈帧保持32Q/FP/PAR和检查点寄存器；异常直接使用原调用方上下文恢复，不伪造正常SP或完成计数。完整64KiB探针栈保留，静态栈顶到DTB余量`0x170`，后续代码增长必须重新核验或扩展几何。

原生模型6/6通过：正向、GCC复位拒绝、未知ID（只读1项）、host角色（只读3项）、DCTL复位（只读4项）和首项后合成故障（保留1项）。正向执行原始VM和两次原始映射，验证496+1个Device页、18次GCC读取和5次控制器读取，零外设写入。模型寄存器值明确为模拟夹具；合成故障不冒充原生总线异常。190项当前编译内存原语、7053字节严格日志、9项损坏拒绝、历史P07/P08读取回归、两个独立审查和新打包门控均通过。

实机正常返回后，原 recovery 已恢复，读回 SHA-256 `8c951baaceed969b29877bc9090d5872ecad0df4cb0e13c2c27c111f5c8ae009`；boot/dtbo/vbmeta 哈希匹配原值。最终 YAAP `boot_completed=1`，诊断FDT属性和暂存目录均不存在。此轮没有替换系统/用户数据分区，也没有启动USB/DMA。

构建、完整派生源码、六份独立模型用例及聚合记录、审查和手机证据冻结在`out/xnu-usb-inventory-probe-attempt1/`：108文件共291,266,546字节，复制与哈希校验通过。源码覆盖为`device/renoace/xnu_usb_inventory_probe/`，构建器`tools/build_renoace_usb_inventory_probe.py`，独立集成器`tools/package_renoace_usb_inventory_probe.py`。少量继承的P08范围注释不能替代这里和模型/审查中记录的P09访问清单；本轮冻结源码保持实测字节。

## 尚需完成的连接路径

下一阶段先准备精确版本与有界SID0x140 SMMU清单，再明确CPU VA、物理RAM和IOVA三种地址及独占DMA页/权限。需要验证缓存同步、TRB/event/setup页所有权、错误返回和停DMA后再解除映射。不能照搬flame的固定bank/地址或把CPU映射成功当作DMA成功。

首个有效电脑连接证明应为受控USB2 EP0枚举与带构建ID的新鲜nonce应答，并由电脑在XNU运行期间实际观测；之后确认端点/DMA静止并返回Linux。当前状态寄存器读回不满足这一条件。完整中断、调度、IOKit、存储、显示及iOS用户态仍待推进。

本轮按既有北京时间09:00截止安排保存状态；P09为截止前最后一次手机实验，后续不再启动新的实机检查。
