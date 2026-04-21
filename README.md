# WeChat Anti-Revoke For Mac

macOS 微信消息防撤回工具，当前首个公开版本为 `v0.1.0`。

仓库地址：
- https://github.com/lerry903/WeChat-Anti-Revoke-For-Mac

克隆：

```bash
git clone https://github.com/lerry903/WeChat-Anti-Revoke-For-Mac.git
```

功能：
- 防止消息被撤回后直接消失
- 在对应消息下方显示“已撤回”提示

## 当前支持

当前稳定支持版本见 [SUPPORTED_VERSIONS.md](./SUPPORTED_VERSIONS.md)。

当前已验证：
- WeChat `4.1.8.107`
- `CFBundleVersion 37342`
- `x86_64`

## 安装

前提：
- macOS
- 已安装微信 App
- 安装前完全退出微信

执行：

```bash
cd Resources
./install.sh
```

安装完成后：
- 重启微信
- 菜单栏会出现“小助手”
- 运行日志在 `/tmp/wechat_anti_revoke_runtime.log`

## 卸载

执行：

```bash
cd Resources
./uninstall.sh
```

## 发布

生成发布包：

```bash
bash scripts/package_release.sh v0.1.0
```

输出目录：

```text
dist/WeChat-Anti-Revoke-For-Mac-v0.1.0/
dist/WeChat-Anti-Revoke-For-Mac-v0.1.0.zip
```

## 问题反馈

提 issue 时请至少提供：
- macOS 版本
- 微信版本
- `CFBundleVersion`
- CPU 架构
- 复现步骤
- `/tmp/wechat_anti_revoke_runtime.log` 相关片段

Issue 地址：
- https://github.com/lerry903/WeChat-Anti-Revoke-For-Mac/issues

## 风险说明

- 微信每次升级后，地址、结构体字段、运行时行为都可能变化，补丁可能立即失效。
- 本项目只承诺仓库内标明的支持版本，不承诺自动兼容未来版本。
- 本项目仅用于技术研究与兼容性分析，请自行承担使用风险。
