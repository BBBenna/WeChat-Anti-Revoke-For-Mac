# Supported Versions

| WeChat Version | CFBundleVersion | Arch | Status | Notes |
| --- | --- | --- | --- | --- |
| 4.1.8.107 | 37342 | x86_64 | supported | Inline anti-revoke hint, immediate refresh, auto-scroll |

## Notes

- 当前补丁按 `CFBundleVersion` 做精确匹配。
- 微信升级后，若 `CFBundleVersion` 变化，默认视为未支持，必须重新适配。
- 新版本适配时，同步更新 [Resources/patch_targets.json](./Resources/patch_targets.json)。
