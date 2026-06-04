# WeChat Anti-Revoke For Mac

macOS 微信消息防撤回工具，当前版本为 `v4.1.10`。

仓库地址：
- https://github.com/lerry903/WeChat-Anti-Revoke-For-Mac

克隆：

```bash
git clone https://github.com/lerry903/WeChat-Anti-Revoke-For-Mac.git
```

## 最新版本（v4.1.10）

**支持微信 4.1.10**，适配微信全新 C++ 架构，通过 DYLD 运行时注入实现防撤回，一键生效。

### 原理

通过注入一个运行时 hook 动态库（`WeChatAntiRevoke.dylib`），利用微信内建的 hook dispatch slot 机制拦截 `isRevokeMessage()` 函数。

### 适用范围

- macOS 微信 4.1.9（CFBundleVersion: 268602）
-       微信 4.1.10 (CFBundleVersion: 268824)
- Apple Silicon（arm64）及 Intel（x86_64）

### 使用

```bash
cd WeChat-Anti-Revoke-For-Mac # 跳转到项目目录
chmod +x patch.sh       # 添加可执行权限
./patch.sh              # 安装防撤回
./patch.sh --uninstall  # 卸载
./patch.sh --help       # 帮助
```

首次运行可能需要约 30 秒（自动解除系统文件保护）。

### 依赖

macOS 系统自带工具，无需额外安装：
- clang（Xcode Command Line Tools）
- python3
- codesign
- tar

如未安装 Xcode Command Line Tools，运行：xcode-select --install

### 已知限制

- **无撤回提示**：当前方案仅静默保留原消息，不会在聊天窗口中显示"对方撤回了一条消息"的提示。你不会知道对方曾经尝试撤回，只能注意到消息没有消失。

- **为什么不能像旧版那样在聊天框内显示提示？**

  旧版微信 macOS（3.x）使用 Objective-C 构建，核心逻辑暴露为 ObjC 方法，可以通过 Method Swizzling 在运行时拦截撤回处理函数，保留原消息的同时调用微信内部的消息插入 API 写入一条提示。

  当前版本（4.1.9）的底层架构已完全不同：核心逻辑迁移到 C++ 实现（仅剩 65 个 ObjC 类，而代码段超过 90MB 均为 C++ 且符号已 strip）。撤回处理不再是独立的"删除旧消息"+"插入提示"两步操作，而是将整个消息对象替换为新的视图模型。在纯二进制补丁方式下，无法构造复杂的函数调用链来插入一条新消息到聊天记录中。

从4.1.9版本开始 copy：https://github.com/a244573118/WeChatIntercept
---
## 风险说明

- 微信每次升级后，地址、结构体字段、运行时行为都可能变化，补丁可能立即失效。
- 本项目只承诺仓库内标明的支持版本，不承诺自动兼容未来版本。
- 本项目仅用于技术研究与兼容性分析，请自行承担使用风险。
