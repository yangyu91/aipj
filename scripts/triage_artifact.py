#!/usr/bin/env python3
"""Collect safe, offline triage facts for an artifact."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile((rb"(?:[\x20-\x7e]\x00){4,}"))

MAGIC_HINTS = [
    # ========== ORIGINAL ==========
    (b"MZ", "PE/Windows executable or DLL"),
    (b"\x7fELF", "ELF executable/shared object"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O universal/fat"),
    (b"PK\x03\x04", "ZIP/APK/JAR/Office container"),
    (b"%PDF", "PDF document"),
    (b"\x1f\x8b", "gzip stream"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!", "RAR archive"),
    (b"dex\n", "Android DEX"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"ustar", "TAR archive marker"),
    (b"hsqs", "SquashFS little-endian filesystem"),
    (b"sqsh", "SquashFS big-endian filesystem"),

    # ========== GAME REVERSING ==========
    (b"UnityFS", "Unity game asset bundle / serialized file"),
    (b"Il2Cpp", "il2cpp metadata / global-metadata.dat"),
    (b"GameAssembly", "Unity GameAssembly.dll/so indicator (text signature)"),
    (b"mono", "Mono runtime embedded (indicator in strings)"),

    # ========== ANDROID KERNEL ==========
    (b"\x7fELF", "ELF — check if .ko kernel module via extension"),
    (b"~module", "Kernel module signature (seen in .ko strings)"),
    (b"vermagic=", "Kernel module version magic string"),
    (b"depends=", "Kernel module dependency string"),
    (b"license=", "Kernel module license string"),

    # ========== CODE GENERATION ==========
    (b"static constexpr uintptr_t", "C++ offsets header (code-gen ready)"),
    (b"process_vm_readv", "Memory read primitive (cheat code present)"),
    (b"process_vm_writev", "Memory write primitive (cheat code present)"),
]

EXTENSION_HINTS = {
    # ========== ORIGINAL ==========
    ".apk": "Android APK",
    ".dex": "Android DEX",
    ".jar": "Java archive",
    ".class": "Java class",
    ".exe": "Windows PE executable",
    ".dll": "Windows PE DLL",
    ".sys": "Windows driver",
    ".elf": "ELF binary",
    ".so": "ELF shared object",
    ".dylib": "Mach-O dynamic library",
    ".ipa": "iOS app archive",
    ".bin": "raw binary/firmware candidate",
    ".img": "disk or firmware image candidate",
    ".pcap": "packet capture",
    ".pcapng": "packet capture",

    # ========== GAME REVERSING ==========
    ".unity3d": "Unity asset bundle",
    ".asset": "Unity asset file",
    ".bytes": "Unity raw bytes / serialized data",
    ".ct": "Cheat Engine table file",
    ".cemu": "Cheat Engine memory dump",

    # ========== ANDROID KERNEL ==========
    ".ko": "Linux kernel module",
    ".mod.c": "Kernel module source",
    ".cmd": "Kernel module build command",

    # ========== CODE GENERATION ==========
    ".mk": "Makefile (Android.mk / Application.mk)",
    ".aidl": "Android AIDL",
    ".cpp": "C++ source file (potential code-gen target)",
    ".h": "C++ header (potential code-gen target)",
}

INDICATOR_PATTERNS = {
    # ========== ORIGINAL ==========
    "urls": re.compile(r"https?://[^\s'\"<>]+", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "windows_paths": re.compile(r"[A-Za-z]:\\[^\s'\"]+"),
    "unix_paths": re.compile(r"/(?:bin|sbin|etc|usr|var|tmp|home|opt)/[^\s'\"]*"),
    "registry": re.compile(r"\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s'\"]+", re.I),
    "emails": re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I),

    # ========== GAME REVERSING ==========
    "memory_patterns": re.compile(r"[0-9A-Fa-f]{8,16}(?:\s*[-+]\s*[0-9A-Fa-f]{1,4})?"),
    "game_offsets": re.compile(r"(?:health|ammo|position|view|matrix|entity|player|recoil|esp|aimbot|trigger)\s*(?:0x[0-9A-Fa-f]{1,8})", re.I),
    "unity_strings": re.compile(r"il2cpp|mono|unity|GameObject|Transform|Vector3", re.I),

    # ========== ANDROID KERNEL ==========
    "kernel_strings": re.compile(r"copy_from_user|copy_to_user|ioctl|file_operations|sys_call_table|kprobes|ftrace|netfilter", re.I),
    "module_strings": re.compile(r"module_init|module_exit|MODULE_LICENSE|MODULE_AUTHOR|MODULE_DESCRIPTION", re.I),
    "root_strings": re.compile(r"magisk|sepolicy|setenforce|su|root|/dev/mem|/proc/pid/mem", re.I),

    # ========== CODE GENERATION ==========
    "code_patterns": re.compile(r"static constexpr uintptr_t|process_vm_readv|process_vm_writev|get_module_base|ndk-build|Android\.mk", re.I),
}

SUSPICIOUS_TERMS = [
    # ========== ORIGINAL ==========
    "CreateProcess", "VirtualAlloc", "WriteProcessMemory", "LoadLibrary", "GetProcAddress",
    "socket", "connect", "InternetOpen", "WinHttp", "Crypt", "OpenSSL",
    "powershell", "cmd.exe", "/bin/sh", "chmod", "wget", "curl", "base64",

    # ========== GAME REVERSING ==========
    "Il2Cpp", "GameObject", "Transform", "Vector3", "Unity",
    "health", "ammo", "position", "viewMatrix", "entityList",
    "ESP", "Aimbot", "NoRecoil", "Triggerbot",
    "Cheat Engine", "ReClass", "pointer chain",

    # ========== ANDROID KERNEL ==========
    "ioctl", "copy_from_user", "copy_to_user", "sys_call_table",
    "kprobe", "ftrace", "netfilter", "module_init", "module_exit",
    "magisk", "sepolicy", "selinux", "KASLR", "vermagic",

    # ========== CODE GENERATION ==========
    "process_vm_readv", "process_vm_writev", "get_module_base",
    "ndk-build", "Android.mk", "Application.mk",
    "offsets.h", "static constexpr uintptr_t",
]


def read_prefix(path: Path, limit: int = 8 * 1024 * 1024) -> bytes:
    with path.open("rb") as f:
        return f.read(limit)


def hash_file(path: Path) -> dict[str, str]:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def strings_from(data: bytes, max_count: int) -> list[str]:
    out: list[str] = []
    for m in PRINTABLE_RE.finditer(data):
        out.append(m.group().decode("utf-8", errors="replace"))
        if len(out) >= max_count:
            return out
    for m in UTF16_RE.finditer(data):
        out.append(m.group().decode("utf-16le", errors="replace"))
        if len(out) >= max_count:
            return out
    return out


def detect_magic(data: bytes) -> list[str]:
    return [name for magic, name in MAGIC_HINTS if data.startswith(magic)] or ["unknown"]


def profile_and_tools(path: Path, magic_hints: list[str], inds: dict[str, list[str]], data_bytes: bytes = b"") -> tuple[list[str], list[str], list[str]]:
    ext = path.suffix.lower()
    joined = " ".join(magic_hints + [EXTENSION_HINTS.get(ext, "")]).lower()
    profiles: list[str] = []
    tools: list[str] = []
    steps: list[str] = []

    # ========== ORIGINAL PROFILES ==========
    if any(x in joined for x in ["apk", "dex", "android"]):
        profiles += ["android", "mobile"]
        tools += ["jadx", "apktool", "frida", "adb", "ghidra for native libraries"]
        steps += ["Decode APK/DEX with jadx/apktool", "Review manifest, exported components, permissions, endpoints, and native libraries"]

    if any(x in joined for x in ["pe", "elf", "mach-o", "executable", "shared object", "dll"]):
        profiles += ["native"]
        tools += ["ghidra", "radare2/rizin", "detect-it-easy", "capa", "floss", "yara", "debugger"]
        steps += ["Map imports/exports/strings to candidate functions", "Open the artifact in a decompiler and label entry points"]

    if any(x in joined for x in ["firmware", "raw binary", "filesystem", "squashfs"]) or ext in {".bin", ".img"}:
        profiles += ["firmware"]
        tools += ["binwalk", "unblob", "ghidra", "qiling/unicorn", "yara"]
        steps += ["Attempt filesystem/container extraction on a copy", "Identify CPU/OS/service startup scripts"]

    if any(x in joined for x in ["packet capture"]) or ext in {".pcap", ".pcapng"}:
        profiles += ["network"]
        tools += ["wireshark", "tshark", "zeek", "network protocol parsers"]
        steps += ["Summarize conversations, endpoints, protocols, and suspicious payloads"]

    if inds.get("urls") or inds.get("ipv4"):
        profiles += ["network-indicators"]
        steps += ["Correlate network indicators with code references before drawing behavior conclusions"]

    if inds.get("suspicious_terms"):
        profiles += ["malware-triage"]
        tools += ["capa", "floss", "yara", "sandbox trace if authorized"]
        steps += ["Run capability detection and validate suspicious terms with xrefs"]

    # ========== GAME REVERSING PROFILE ==========
    game_indicators = (
        "unity" in joined or "il2cpp" in joined or "gameassembly" in joined or
        inds.get("game_offsets") or inds.get("unity_strings") or
        any(t in joined for t in ["esp", "aimbot", "health", "ammo", "position"]) or
        ext in {".ct", ".cemu", ".unity3d", ".asset", ".bytes"}
    )
    if game_indicators:
        profiles += ["game"]
        tools += ["Cheat Engine", "ReClass.NET", "ghidra", "frida"]
        steps += [
            "Perform pointer-chain scanning with Cheat Engine / ReClass.NET",
            "Validate game offsets via freeze/modify/observe workflow",
            "Locate view-projection matrix and entity list structures",
        ]

    # ========== ANDROID KERNEL PROFILE ==========
    kernel_indicators = (
        ext == ".ko" or
        inds.get("kernel_strings") or inds.get("module_strings") or inds.get("root_strings") or
        any(t in joined for t in ["copy_from_user", "ioctl", "sys_call_table", "module_init", "vermagic"])
    )
    if kernel_indicators:
        profiles += ["android-kernel"]
        tools += ["ghidra", "radare2", "frida", "objection", "magisk", "adb", "ndk-build"]
        steps += [
            "Extract ioctl command codes and map file_operations structure",
            "Analyze syscall table hijacking and kprobes/ftrace hooks",
            "Document kernel version, KASLR status, and SELinux context",
            "Design safe local test harness for .ko module validation",
        ]

    # ========== CODE GENERATION PROFILE ==========
    code_indicators = (
        inds.get("code_patterns") or
        any(t in joined for t in ["offsets.h", "ndk-build", "android.mk", "process_vm_readv"]) or
        ext in {".mk", ".cpp", ".h", ".aidl"}
    )
    if code_indicators:
        profiles += ["code-gen"]
        tools += ["NDK (clang++, ndk-build)", "ghidra", "jadx", "aide (on-device)"]
        steps += [
            "Generate evidence-to-code mapping table",
            "Scaffold jni/ project with Android.mk and Application.mk",
            "Implement read/write primitives (process_vm_readv/writev + fallback)",
            "Build and test with ndk-build in local emulator",
            "Include online risk warning in final deliverable",
        ]

    # ========== DEDUPLICATION ==========
    dedup = lambda xs: list(dict.fromkeys(xs))
    return (
        dedup(profiles) or ["generic"],
        dedup(tools),
        dedup(steps) or ["Continue static triage with strings, metadata, and file-format analysis"]
    )


def indicators(strings: list[str]) -> dict[str, list[str]]:
    joined = "\n".join(strings)
    result: dict[str, list[str]] = {}
    for name, pat in INDICATOR_PATTERNS.items():
        vals = sorted(set(pat.findall(joined)))[:50]
        if vals:
            result[name] = vals
    suspicious = sorted({term for term in SUSPICIOUS_TERMS if term.lower() in joined.lower()})
    if suspicious:
        result["suspicious_terms"] = suspicious
    return result


def markdown_report(data: dict) -> str:
    lines = [
        "# Artifact Triage",
        "",
        f"- Path: `{data['path']}`",
        f"- Size: {data['size']} bytes",
        f"- SHA-256: `{data['hashes']['sha256']}`",
        f"- Extension hint: {data.get('extension_hint') or '-'}",
        f"- Magic hints: {', '.join(data['magic_hints'])}",
        f"- Prefix entropy: {data['prefix_entropy']:.3f}",
        f"- Suggested profiles: {', '.join(data.get('profiles', []))}",
        f"- Generated UTC: {data['generated_utc']}",
        "",
        "## Recommended local tools",
    ]
    if data.get("recommended_tools"):
        for tool in data["recommended_tools"]:
            lines.append(f"- {tool}")
    else:
        lines.append("- No specific tool recommendation yet.")
    lines += [
        "",
        "## Recommended next steps",
    ]
    for step in data.get("recommended_next_steps", []):
        lines.append(f"- {step}")
    lines += [
        "",
        "## Indicators",
    ]
    if data["indicators"]:
        for k, vals in data["indicators"].items():
            lines.append(f"### {k}")
            for v in vals[:20]:
                lines.append(f"- `{v}`")
    else:
        lines.append("No high-signal indicators found in extracted strings.")
    lines += ["", "## Sample strings", ""]
    for s in data["strings"][:80]:
        safe = s.replace("`", "'")
        lines.append(f"- `{safe}`")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Triage one artifact without executing it")
    parser.add_argument("artifact", help="Path to artifact")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--max-strings", type=int, default=500, help="Maximum strings to store")
    args = parser.parse_args()

    path = Path(args.artifact).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        raise SystemExit(f"not a file: {path}")

    prefix = read_prefix(path)
    strs = strings_from(prefix, args.max_strings)
    inds = indicators(strs)
    profiles, recommended_tools, next_steps = profile_and_tools(path, detect_magic(prefix), inds, prefix)
    data = {
        "path": str(path),
        "name": path.name,
        "size": os.path.getsize(path),
        "hashes": hash_file(path),
        "extension_hint": EXTENSION_HINTS.get(path.suffix.lower(), ""),
        "magic_hints": detect_magic(prefix),
        "prefix_entropy": entropy(prefix),
        "strings": strs,
        "indicators": inds,
        "profiles": profiles,
        "recommended_tools": recommended_tools,
        "recommended_next_steps": next_steps,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "notes": "Offline triage only; artifact was not executed.",
    }
    stem = path.name.replace(os.sep, "_")
    json_path = out / f"{stem}.triage.json"
    md_path = out / f"{stem}.triage.md"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(markdown_report(data), encoding="utf-8")
    print(json_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())