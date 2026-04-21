#!/usr/bin/env python3

import argparse
import binascii
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ARCH_CPU = {
    "x86_64": 0x01000007,
    "arm64": 0x0100000C,
}

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
BACKUP_SUFFIX = ".wechat-anti-revoke.bak"
LEGACY_BACKUP_SUFFIX = ".wechat-extension.bak"
RUNTIME_LOADER_NAME = "WeChatAntiRevokeLoader.dylib"
LEGACY_RUNTIME_LOADER_NAME = "WeChatExtensionLoader.dylib"
LEGACY_FRAMEWORK_NAME = "WeChatExtension.framework"


def read_plist_version(app_path: Path) -> str:
    with app_path.joinpath("Contents/Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    return str(info["CFBundleVersion"])


def load_config(config_path: Path, version: str) -> dict:
    with config_path.open("r", encoding="utf-8") as handle:
        items = json.load(handle)
    for item in items:
        if str(item["version"]) == version:
            return item
    supported = ", ".join(sorted(str(item["version"]) for item in items))
    raise RuntimeError(f"暂不支持当前微信版本 {version}，已支持版本：{supported}")


def group_targets(config: dict) -> dict:
    grouped = {}
    for target in config["targets"]:
        binary = target.get("binary", "Contents/MacOS/WeChat")
        grouped.setdefault(binary, []).append(target)
    return grouped


def backup_path(binary: Path) -> Path:
    return binary.with_name(binary.name + BACKUP_SUFFIX)


def legacy_backup_path(binary: Path) -> Path:
    return binary.with_name(binary.name + LEGACY_BACKUP_SUFFIX)


def restore_binary(binary: Path) -> bool:
    backup = backup_path(binary)
    if not backup.exists():
        backup = legacy_backup_path(binary)
    if not backup.exists():
        return False
    shutil.copy2(backup, binary)
    backup.unlink()
    return True


def ensure_clean_binary(binary: Path) -> None:
    backup = backup_path(binary)
    legacy_backup = legacy_backup_path(binary)
    if backup.exists():
        shutil.copy2(backup, binary)
    elif legacy_backup.exists():
        shutil.copy2(legacy_backup, binary)
        shutil.copy2(legacy_backup, backup)
    else:
        shutil.copy2(binary, backup)


def patch_binary(binary: Path, targets: list[dict]) -> None:
    entries = []
    for target in targets:
        for entry in target["entries"]:
            arch = entry["arch"]
            entries.append(
                {
                    "arch": arch,
                    "cpu": ARCH_CPU[arch],
                    "addr": int(entry["addr"], 16),
                    "asm": binascii.unhexlify(entry["asm"]),
                    "identifier": target["identifier"],
                }
            )

    with binary.open("r+b") as handle:
        magic_bytes = handle.read(4)
        if len(magic_bytes) != 4:
            raise RuntimeError(f"无法读取文件头：{binary}")
        magic_be = struct.unpack(">I", magic_bytes)[0]
        is_fat = magic_be in (FAT_MAGIC, FAT_CIGAM)
        is_swapped_fat = magic_be == FAT_CIGAM

        patched = 0
        if is_fat:
            raw_nfat = handle.read(4)
            if len(raw_nfat) != 4:
                raise RuntimeError(f"无法读取 fat header：{binary}")
            nfat = struct.unpack(">I", raw_nfat)[0] if not is_swapped_fat else struct.unpack("<I", raw_nfat)[0]
            slices = []
            for _ in range(nfat):
                arch_data = handle.read(20)
                if len(arch_data) != 20:
                    raise RuntimeError(f"无法读取 fat arch：{binary}")
                cpu = struct.unpack(">I", arch_data[0:4])[0] if not is_swapped_fat else struct.unpack("<I", arch_data[0:4])[0]
                offset = struct.unpack(">I", arch_data[8:12])[0] if not is_swapped_fat else struct.unpack("<I", arch_data[8:12])[0]
                slices.append((cpu, offset))

            for cpu, offset in slices:
                for entry in entries:
                    if entry["cpu"] != cpu:
                        continue
                    patch_one_slice(handle, offset, entry["addr"], entry["asm"], entry["arch"], binary, entry["identifier"])
                    patched += 1
        else:
            handle.seek(0)
            header = handle.read(32)
            if len(header) != 32:
                raise RuntimeError(f"无法读取 mach header：{binary}")
            magic = struct.unpack("<I", header[0:4])[0]
            cpu = struct.unpack("<i", header[4:8])[0]
            if magic != MH_MAGIC_64:
                raise RuntimeError(f"非 64 位 Mach-O：{binary}")
            for entry in entries:
                if cpu != struct.unpack("<i", struct.pack("<I", entry["cpu"]))[0]:
                    continue
                patch_one_slice(handle, 0, entry["addr"], entry["asm"], entry["arch"], binary, entry["identifier"])
                patched += 1

        if patched == 0:
            raise RuntimeError(f"未找到可匹配架构：{binary}")


def patch_one_slice(handle, slice_offset: int, target_va: int, patch: bytes, arch_name: str, binary: Path, identifier: str) -> None:
    handle.seek(slice_offset)
    header = handle.read(32)
    if len(header) != 32:
        raise RuntimeError(f"无法读取 slice header：{binary}")

    magic = struct.unpack("<I", header[0:4])[0]
    ncmds = struct.unpack("<I", header[16:20])[0]
    if magic != MH_MAGIC_64:
        raise RuntimeError(f"slice 不是 64 位 Mach-O：{binary}")

    lc_offset = slice_offset + 32
    for _ in range(ncmds):
        handle.seek(lc_offset)
        lc_head = handle.read(8)
        if len(lc_head) != 8:
            raise RuntimeError(f"无法读取 load command：{binary}")
        cmd, cmdsize = struct.unpack("<II", lc_head)
        if cmd == LC_SEGMENT_64:
            seg_data = handle.read(64)
            if len(seg_data) != 64:
                raise RuntimeError(f"无法读取 segment：{binary}")
            vmaddr = struct.unpack("<Q", seg_data[16:24])[0]
            vmsize = struct.unpack("<Q", seg_data[24:32])[0]
            fileoff = struct.unpack("<Q", seg_data[32:40])[0]
            if vmaddr <= target_va < vmaddr + vmsize:
                file_offset = slice_offset + fileoff + (target_va - vmaddr)
                handle.seek(file_offset)
                handle.write(patch)
                print(f"[{arch_name}] patched {identifier} at {binary} va=0x{target_va:x} fileoff=0x{file_offset:x}")
                return
        lc_offset += cmdsize

    raise RuntimeError(f"未找到地址 0x{target_va:x} 所在 segment：{binary}")


def cleanup_legacy_injection(app_path: Path) -> None:
    app_exec = app_path / "Contents/MacOS/WeChat"
    legacy_backup = app_exec.with_name(app_exec.name + "_backup")
    legacy_framework = app_path / "Contents/MacOS" / LEGACY_FRAMEWORK_NAME
    runtime_loader = app_path / "Contents/MacOS" / RUNTIME_LOADER_NAME
    legacy_runtime_loader = app_path / "Contents/MacOS" / LEGACY_RUNTIME_LOADER_NAME

    if legacy_backup.exists():
        shutil.copy2(legacy_backup, app_exec)
        legacy_backup.unlink()
    if legacy_framework.exists():
        shutil.rmtree(legacy_framework)
    if runtime_loader.exists():
        runtime_loader.unlink()
    if legacy_runtime_loader.exists():
        legacy_runtime_loader.unlink()


def build_runtime_loader(source_path: Path, output_path: Path) -> None:
    sdk_path = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
    min_version = os.environ.get("MACOSX_DEPLOYMENT_TARGET", "11.0")
    subprocess.run(
        [
            "clang",
            "-dynamiclib",
            "-fobjc-arc",
            "-arch",
            "x86_64",
            "-mmacosx-version-min=" + min_version,
            "-isysroot",
            sdk_path,
            "-framework",
            "AppKit",
            "-framework",
            "Foundation",
            str(source_path),
            "-o",
            str(output_path),
        ],
        check=True,
    )


def install_runtime_loader(app_path: Path, loader_binary: Path, insert_dylib_path: Path) -> None:
    app_exec = app_path / "Contents/MacOS/WeChat"
    app_exec_backup = app_exec.with_name(app_exec.name + "_backup")
    target_loader = app_path / "Contents/MacOS" / RUNTIME_LOADER_NAME
    loader_ref = f"@executable_path/{RUNTIME_LOADER_NAME}"

    shutil.copy2(app_exec, app_exec_backup)
    shutil.copy2(loader_binary, target_loader)
    target_loader.chmod(0o755)

    subprocess.run(
        [
            str(insert_dylib_path),
            "--all-yes",
            loader_ref,
            str(app_exec_backup),
            str(app_exec),
        ],
        check=True,
    )


def codesign_app(app_path: Path) -> None:
    subprocess.run(["codesign", "--remove-sign", str(app_path)], check=False)
    subprocess.run(["codesign", "--force", "--deep", "--sign", "-", str(app_path)], check=True)
    subprocess.run(["xattr", "-c", str(app_path)], check=False)


def install(app_path: Path, config_path: Path) -> None:
    version = read_plist_version(app_path)
    config = load_config(config_path, version)
    cleanup_legacy_injection(app_path)

    grouped = group_targets(config)
    for binary_rel, targets in grouped.items():
        binary = app_path / binary_rel
        if not binary.exists():
            raise RuntimeError(f"未找到目标文件：{binary}")
        ensure_clean_binary(binary)
        patch_binary(binary, targets)

    rely_dir = config_path.parent
    source_path = rely_dir / "anti_revoke_runtime.m"
    insert_dylib_path = rely_dir / "insert_dylib"
    if not source_path.exists():
        raise RuntimeError(f"未找到运行时源码：{source_path}")
    if not insert_dylib_path.exists():
        raise RuntimeError(f"未找到注入工具：{insert_dylib_path}")

    with tempfile.TemporaryDirectory(prefix="wechat-anti-revoke-loader-") as tmp_dir:
        loader_binary = Path(tmp_dir) / RUNTIME_LOADER_NAME
        build_runtime_loader(source_path, loader_binary)
        install_runtime_loader(app_path, loader_binary, insert_dylib_path)

    codesign_app(app_path)
    print(f"安装完成，当前微信版本：{version}")


def uninstall(app_path: Path, config_path: Path) -> None:
    restored = False
    cleanup_legacy_injection(app_path)

    with config_path.open("r", encoding="utf-8") as handle:
        items = json.load(handle)
    binaries = sorted(
        {
            item.get("binary", "Contents/MacOS/WeChat")
            for config in items
            for item in config["targets"]
        }
    )

    for binary_rel in binaries:
        binary = app_path / binary_rel
        if binary.exists():
            restored = restore_binary(binary) or restored

    if restored:
        print("已恢复原始文件，重启微信生效。")
    else:
        print("未发现可恢复的补丁备份。")


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch WeChat anti-revoke support.")
    parser.add_argument("action", choices=["install", "uninstall"])
    parser.add_argument("--app", required=True, help="Path to WeChat.app")
    parser.add_argument("--config", required=True, help="Path to patch_targets.json")
    args = parser.parse_args()

    app_path = Path(args.app).expanduser().resolve()
    config_path = Path(args.config).expanduser().resolve()

    try:
        if args.action == "install":
            install(app_path, config_path)
        else:
            uninstall(app_path, config_path)
    except Exception as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
