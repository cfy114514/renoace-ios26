# XNU 运行期 USB 连接：后续实现契约

这是基于 P09 实机结果和固定源码的后续设计，**尚未执行 SMMU 读取、DMA 配置、USB 枚举或主机应答**。当前已知 DWC3.1/DRD/device 角色、控制器halt、GCC时钟和core-reset只读状态，不能把这些当作电脑连接证明。

## 先建立可复核的 SMMU 只读观察

本机 DT 的 apps-SMMU 为`qcom,qsmmu-v500`，物理范围`0x15000000/0x100000`；USB0 使用 SID`0x140`、mask0。初次原型只需要 GR0 的一个CPU Device/XN页`0x15000000/0x1000`，不读取TBU/TCU独立区域、GR1、context bank或固件页表。

**访问前提尚未验证。** 固定OPPO驱动在寄存器操作前处理互连带宽、供电与时钟；apps-SMMU节点带`qcom,skip-init`且没有可直接据此发明GCC位掩码的父时钟列表。USB的GCC和控制器访问不证明SMMU CPU权限、NoC/时钟保持或DMA所有权。先解决这一访问契约，再制作目标探针；软件时间上限无法救回永久卡住的MMIO加载。

| 读取项 | GR0偏移 | 必须采用的边界与解码 |
|---|---|---|
| sCR0 | `0x00` | 只记录CLIENTPD0、EXIDENABLE3、USFCFG10等策略，不写 |
| IDR0 | `0x20` | SMS27、EXIDS8、NUMSIDB12:9、NUMSMRG7:0 |
| IDR1 | `0x24` | PAGESIZE31、NUMPAGENDXB30:28、NUMS2CB23:16、NUMCB7:0 |
| SMR(i) | `0x800+4*i` | 在能力确认的N项内，且末地址不超过本页 |
| S2CR(i) | `0xc00+4*i` | 同样限制N项和本页边界 |

SMS=1时，N是NUMSMRG的原数值；初版只接受1..255，0不解释成256。要求`0x800+4*N<=0x1000`及`0xc00+4*N<=0x1000`，所有访问均为对齐32位读取。两次完整扫描包含三个能力/策略字及N对表项，最多1026次加载；任一值变化即拒绝稳定扫描结论。

在确认的legacy格式（EXIDENABLE=0且SID宽度一致）下，SMR有效位31、ID低15位、mask位30:16；mask位1表示忽略对应SID位。SID140匹配条件为：

```text
valid && (((0x140 ^ id) & (~mask & 0x7fff)) == 0)
```

保留所有匹配，不任取第一项。S2CR TYPE位17:16为translate0/bypass1/fault2/reserved3，CBNDX低8位；translate的索引必须小于NUMCB，但此阶段只记录索引。没有可见匹配不能证明bank/stream空闲或DMA可用。

扩展ID模式把有效位放在S2CR位10，SMR掩码格式不同；初版仅保留有界原始表项并拒绝按legacy解释。SMS=0的stream-index模式也单独标记不支持。Linux通过写未使用SMR来探测mask位宽的流程不能用于本次只读设计。

IDR1页大小为4KiB或64KiB，global范围按`(1<<(NUMPAGENDXB+1))<<page_shift`计算；检查移位/加法溢出、NUMS2CB<=NUMCB和推算布局在声明1MiB内。这只验证布局，不据此访问context bank。

原始表项需要独立预留、有界且不与内核/栈/ADT/页表重叠的RAM缓冲区；最多255对原始32位表项为2040字节。输出必须有长度、版本和CRC/哈希绑定，遇到匹配项或日志容量不足应明确拒绝，不能静默截断。当前P09日志7053/8192字节、RX入口1504/2048字节、探针栈顶到DTB仅368字节；新增功能前必须重新设计记录/文本和装载几何。

## 再设计独占 DMA 与主机证明

明确区分CPU VA、物理RAM和IOVA。事件、setup、control、TRB和descriptor页需要显式独占、页对齐、权限最小且彼此/与已有对象不重叠；只映射实际需要的SID140页面。记录的硬件地址宽度不证明SMMU/HYP允许DMA。不能照搬flame的固定context bank、宽泛身份块或内存地址。

原型先用实际编译指令和明确标注的设备模型验证缓存同步/屏障、队列所有权、错误路径、范围拒绝以及DMA静止流程。除后续明确实现的自有资源外，不改sCR0、SMR/S2CR、bypass、CBAR/TTBR/TCR/SCTLR、ATS/RESUME/TLBI，也不清除故障状态或遍历固件TTBR指针。

首个连接证明采用有界的USB2 EP0描述符/构建ID与新鲜nonce挑战应答；电脑必须在XNU仍运行时实际观察并匹配应答。主机侧接入方式应先适配当前Windows环境。完成或失败后先停止端点、确认没有TRB获取/事件写入，再解除IOVA和恢复自己保存的状态，最后回交Linux。返回YAAP后读取日志仍只是恢复通道。

更完整的USB代码需要专用编译RX区域和相应内核CI/布局验证，不应继续假定P09剩余544字节文本填充足够。现有公开macOS CI授权与固定依赖方案可用于后续受审查源码实现；本轮没有启动新云构建或硬件实验。

## 源码与证据

固定OPPO源码提交`289d6118ef783a281a8ecf0378e3c560ff6976c4`，实际为monolithic `drivers/iommu/arm-smmu.c`和`arm-smmu-regs.h`。文件SHA-256分别为`387fdb60492e99ae6b54243393b0e76df2c4ec79e2b09a482e4a9611671d223d`和`d47fff32ec38d2631b7c96faeac9d38fbb4c527b71e2241c8aabf9ab4e341edd`。不能因为较新分拆文件不存在而改用未固定版本的实现推断本机。

完整固定源缓存、边界/格式说明及伪代码在`out/analysis/p10-smmu-inventory-contract.*`；P09实机寄存器判读在`out/analysis/p09-actual-inventory.*`。Flame的未匹配SID复位和HYP拒绝bypass是参考机现象，仍不是Reno Ace的实测结果。实机已完成范围见[STAGE12.md](STAGE12.md)。
