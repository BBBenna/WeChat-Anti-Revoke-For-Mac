#!/bin/bash

set -e

wechat_path="/Applications/WeChat.app"
if [ ! -d "$wechat_path" ]; then
    wechat_path="/Applications/微信.app"
fi

if [ ! -d "$wechat_path" ]; then
    echo -e "\n\n应用程序文件夹中未发现微信，请检查微信是否有重命名或者移动路径位置"
    exit 1
fi

if pgrep -x "WeChat" >/dev/null 2>&1; then
    echo -e "\n\n请先完全退出微信后再卸载。"
    exit 1
fi

shell_path="$(cd "$(dirname "$0")" && pwd)"
config_path="${shell_path}/patch_targets.json"
patcher_path="${shell_path}/patch_wechat.py"

if [ ! -w "$wechat_path" ]; then
    echo -e "\n\n为了恢复微信原始文件, 请输入密码："
    sudo chown -R "$(whoami)" "$wechat_path"
fi

python3 "${patcher_path}" uninstall --app "${wechat_path}" --config "${config_path}"
echo -e "\n\tWeChat Anti-Revoke For Mac 已卸载，请重启微信。"
