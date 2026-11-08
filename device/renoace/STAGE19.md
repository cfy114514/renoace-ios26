# 第十九阶段：iOS 用户态输入离线清点

本阶段只清点工作区已有文件，不下载 IPSW、不构建 UEFI、不操作手机、USB 或 DMA。

```powershell
python tools/audit_renoace_ios_artifacts.py
```

可恢复输入清单保存在 `device/renoace/IOS_INPUT_MANIFEST.json`。它固定目标身份、允许的本地落盘路径、每个必需组件的验收方式和不下载的默认策略。恢复时先把用户提供的 IPSW 放到清单路径，再按清单命令提取和记录 SHA-256；清单中的 `ready_for_darwinboot` 在所有验收项通过前必须保持 `false`。

当前 `board.toml` 声明目标为 iPhone18,2 / iOS 26.5.2 / 23F84，但本地没有 IPSW、KernelCache、iOS DeviceTree、StaticTrustCache、Cryptex、root/system volume 或 dyld shared cache。固定 `references/UniXNU-ios26` 源文件和 21 个驱动/kit 子模块已经在本地恢复；`UniXNU-zeta` 只有转换脚本，没有用户态二进制。

恢复后的 `unixnu --help`、`status`、`defconfig renoace_research_defconfig` 和显式绑定当前 source/worktree 的 `tree` 均可运行；树输出在 `out/unixnu/renoace/tree`。普通 `tree` 调用仍会把源根解析到主工作树，因此后续命令必须显式绑定 `GIT_DIR`/`GIT_WORK_TREE`，避免误用另一份 checkout。

因此目前不能声称有可启动的 iOS 用户态。后续需要用户提供或授权使用匹配的本地 IPSW/固件输入，并初始化固定 UniXNU 源码/子模块后，才能继续 DarwinBoot、rootfs 和 dyld 兼容工作。
