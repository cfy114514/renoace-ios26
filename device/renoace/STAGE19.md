# 第十九阶段：iOS 用户态输入离线清点

本阶段只清点工作区已有文件，不下载 IPSW、不构建 UEFI、不操作手机、USB 或 DMA。

```powershell
python tools/audit_renoace_ios_artifacts.py
```

当前 `board.toml` 声明目标为 iPhone18,2 / iOS 26.5.2 / 23F84，但本地没有 IPSW、KernelCache、iOS DeviceTree、StaticTrustCache、Cryptex、root/system volume 或 dyld shared cache。固定 `references/UniXNU-ios26` 源文件已从本地 Git 对象恢复，但其 18 个驱动/kit 子模块仍未初始化；`UniXNU-zeta` 只有转换脚本，没有用户态二进制。

因此目前不能声称有可启动的 iOS 用户态。后续需要用户提供或授权使用匹配的本地 IPSW/固件输入，并初始化固定 UniXNU 源码/子模块后，才能继续 DarwinBoot、rootfs 和 dyld 兼容工作。
