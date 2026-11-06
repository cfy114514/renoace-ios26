# Reno Ace XNU kernel build

Reno Ace / SM8150 的 XNU 12377 源码编译研究。[正式零基址修复云构建成功](https://github.com/cfy114514/renoace-ios26/actions/runs/42306878464)，32项源码、编译证据和机器码核验通过。内核23,005,792字节，SHA-256 `c361eda7d383619ec76c814a4f2121955547fadaa8235131d6849aa14d995743`。

主工作区已使用明确记录观测补丁的临时诊断，在 Reno Ace 上执行完整 `arm_vm_init` 并返回原 Android；原 recovery 已恢复。完整 XNU/iOS、真实定时器中断和 XNU 运行期电脑连接尚未实现。

参见 [CI 说明](ci/README.md)。仓库包含设备编译输入与 CI 工具，ArmCpu 许可文件随源码保留。
