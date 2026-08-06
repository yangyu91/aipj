#!/usr/bin/env python3
"""Audit local reverse-engineering tooling and recommend next tools by profile."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CATALOG = [
    # ========== ORIGINAL TOOLS ==========
    {"name":"Ghidra","repo":"https://github.com/NationalSecurityAgency/ghidra","stars":70306,"profile":["native","firmware","vuln"],"commands":["ghidraRun","analyzeHeadless"],"purpose":"decompilation and SRE projects"},
    {"name":"jadx","repo":"https://github.com/skylot/jadx","stars":49250,"profile":["android","mobile"],"commands":["jadx","jadx-gui"],"purpose":"DEX/APK decompilation"},
    {"name":"x64dbg","repo":"https://github.com/x64dbg/x64dbg","stars":48770,"profile":["windows","dynamic","native"],"commands":["x64dbg","x32dbg"],"purpose":"Windows user-mode debugging"},
    {"name":"Apktool","repo":"https://github.com/iBotPeaches/Apktool","stars":24904,"profile":["android","mobile"],"commands":["apktool"],"purpose":"APK resource and smali analysis"},
    {"name":"radare2","repo":"https://github.com/radareorg/radare2","stars":24225,"profile":["native","firmware"],"commands":["r2","rabin2","rahash2"],"purpose":"CLI reverse engineering framework"},
    {"name":"Frida","repo":"https://github.com/frida/frida","stars":21168,"profile":["dynamic","android","mobile","native"],"commands":["frida","frida-trace"],"purpose":"dynamic instrumentation"},
    {"name":"Binwalk","repo":"https://github.com/ReFirmLabs/binwalk","stars":14083,"profile":["firmware"],"commands":["binwalk"],"purpose":"firmware extraction and carving"},
    {"name":"Detect It Easy","repo":"https://github.com/horsicq/Detect-It-Easy","stars":11062,"profile":["native","triage"],"commands":["diec","die"],"purpose":"file/compiler/packer identification"},
    {"name":"pwndbg","repo":"https://github.com/pwndbg/pwndbg","stars":10609,"profile":["native","dynamic","vuln"],"commands":["gdb"],"purpose":"GDB reverse/debug enhancement"},
    {"name":"YARA","repo":"https://github.com/VirusTotal/yara","stars":9721,"profile":["triage","memory","malware"],"commands":["yara"],"purpose":"pattern matching"},
    {"name":"Unicorn","repo":"https://github.com/unicorn-engine/unicorn","stars":9126,"profile":["emulation","firmware","native"],"commands":["python"],"python_modules":["unicorn"],"purpose":"CPU emulation"},
    {"name":"angr","repo":"https://github.com/angr/angr","stars":8921,"profile":["native","vuln"],"commands":["python"],"python_modules":["angr"],"purpose":"symbolic execution and CFG analysis"},
    {"name":"Capstone","repo":"https://github.com/capstone-engine/capstone","stars":8872,"profile":["native","emulation"],"commands":["python"],"python_modules":["capstone"],"purpose":"disassembly library"},
    {"name":"RetDec","repo":"https://github.com/avast/retdec","stars":8566,"profile":["native"],"commands":["retdec-decompiler"],"purpose":"machine-code decompilation"},
    {"name":"GEF","repo":"https://github.com/hugsy/gef","stars":8251,"profile":["native","dynamic","vuln"],"commands":["gdb"],"purpose":"GDB enhancement"},
    {"name":"AFL++","repo":"https://github.com/AFLplusplus/AFLplusplus","stars":6628,"profile":["vuln","fuzzing"],"commands":["afl-fuzz","afl-clang-fast"],"purpose":"coverage-guided fuzzing"},
    {"name":"syzkaller","repo":"https://github.com/google/syzkaller","stars":6249,"profile":["kernel","vuln","fuzzing"],"commands":["syz-manager"],"purpose":"kernel fuzzing"},
    {"name":"capa","repo":"https://github.com/mandiant/capa","stars":6080,"profile":["triage","native","malware"],"commands":["capa"],"purpose":"capability detection"},
    {"name":"Qiling","repo":"https://github.com/qilingframework/qiling","stars":5986,"profile":["emulation","firmware","native"],"commands":["python"],"python_modules":["qiling"],"purpose":"instrumentable binary emulation"},
    {"name":"LIEF","repo":"https://github.com/lief-project/LIEF","stars":5460,"profile":["native","triage"],"commands":["python"],"python_modules":["lief"],"purpose":"executable format parsing"},
    {"name":"Volatility 3","repo":"https://github.com/volatilityfoundation/volatility3","stars":4223,"profile":["memory"],"commands":["vol","vol.py"],"purpose":"memory forensics"},
    {"name":"FLOSS","repo":"https://github.com/mandiant/flare-floss","stars":4066,"profile":["triage","malware","native"],"commands":["floss"],"purpose":"obfuscated string extraction"},
    {"name":"Rizin","repo":"https://github.com/rizinorg/rizin","stars":3693,"profile":["native","firmware"],"commands":["rizin","rz-bin"],"purpose":"CLI reverse engineering framework"},

    # ========== GAME REVERSING TOOLS ==========
    {"name":"Cheat Engine","repo":"https://github.com/cheat-engine/cheat-engine","stars":17893,"profile":["game","windows"],"commands":["cheatengine-x86_64"],"purpose":"game memory scanning, pointer-chain discovery"},
    {"name":"ReClass.NET","repo":"https://github.com/ReClassNET/ReClassNET","stars":4224,"profile":["game","windows"],"commands":["ReClass.NET.exe"],"purpose":"game memory structure reverse engineering"},

    # ========== ANDROID KERNEL / CHEAT TOOLS ==========
    {"name":"Magisk","repo":"https://github.com/topjohnwu/Magisk","stars":55221,"profile":["android-kernel","android"],"commands":["magisk"],"purpose":"Android root/hiding and module management (on-device)"},
    {"name":"Objection","repo":"https://github.com/sensepost/objection","stars":7508,"profile":["android","android-kernel","mobile"],"commands":["objection"],"purpose":"Android/iOS runtime exploration"},
    {"name":"NDK (clang++)","repo":"https://developer.android.com/ndk","stars":0,"profile":["android-kernel","code-gen"],"commands":["clang++","ndk-build"],"purpose":"Android C++ compilation toolchain"},
    {"name":"AIDE","repo":"https://aide.en.softonic.com/android","stars":0,"profile":["code-gen","android"],"commands":[],"purpose":"on-device Android C++ IDE/build (requires device install)"},
    # ========== WEB PENETRATION TESTING TOOLS ==========
    {"name":"ffuf","repo":"https://github.com/ffuf/ffuf","stars":13000,"profile":["web"],"commands":["ffuf"],"purpose":"web fuzzing and directory busting"},
    {"name":"sqlmap","repo":"https://github.com/sqlmapproject/sqlmap","stars":33000,"profile":["web","vuln"],"commands":["sqlmap"],"purpose":"automatic SQL injection detection"},
    {"name":"gobuster","repo":"https://github.com/OJ/gobuster","stars":10000,"profile":["web"],"commands":["gobuster"],"purpose":"directory/file brute-forcing"},
    {"name":"dalfox","repo":"https://github.com/hahwul/dalfox","stars":3500,"profile":["web"],"commands":["dalfox"],"purpose":"XSS scanning and exploitation"},
    {"name":"hydra","repo":"https://github.com/vanhauser-thc/thc-hydra","stars":10000,"profile":["web","network"],"commands":["hydra"],"purpose":"password brute-forcing (HTTP, SSH, etc.)"},
    {"name":"Wireshark","repo":"https://github.com/wireshark/wireshark","stars":0,"profile":["network","web"],"commands":["wireshark","tshark"],"purpose":"traffic capture and analysis"},
    {"name":"mitmproxy","repo":"https://github.com/mitmproxy/mitmproxy","stars":37000,"profile":["network","web"],"commands":["mitmproxy","mitmdump"],"purpose":"HTTP/HTTPS interception"},
    {"name":"Scapy","repo":"https://github.com/secdev/scapy","stars":11500,"profile":["network"],"commands":["python"],"python_modules":["scapy"],"purpose":"packet crafting and replay"},
]


def check_module(module: str) -> bool:
    try:
        subprocess.run(["python", "-c", f"import {module}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception:
        return False


def audit(profile: str = "auto") -> dict:
    rows = []
    selected = []
    for item in CATALOG:
        if profile != "auto" and profile not in item["profile"]:
            continue
        found_cmds = [cmd for cmd in item.get("commands", []) if shutil.which(cmd)]
        found_mods = [m for m in item.get("python_modules", []) if check_module(m)]
        installed = bool(found_cmds or found_mods)
        row = dict(item)
        row["installed"] = installed
        row["found_commands"] = found_cmds
        row["found_python_modules"] = found_mods
        rows.append(row)
        selected.append(row)
    installed_count = sum(1 for r in selected if r["installed"])
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "installed_count": installed_count,
        "total_checked": len(selected),
        "tools": sorted(selected, key=lambda x: (-int(x["installed"]), -x["stars"], x["name"].lower())),
        "recommended_missing": [r for r in sorted(selected, key=lambda x: -x["stars"]) if not r["installed"]][:10],
    }


def to_markdown(data: dict) -> str:
    lines = [
        "# Reverse Tool Audit",
        "",
        f"- Generated UTC: {data['generated_utc']}",
        f"- Profile: {data['profile']}",
        f"- Installed: {data['installed_count']} / {data['total_checked']}",
        "",
        "## Detected tools",
        "| Status | Tool | Stars | Purpose | Found | Repo |",
        "|---|---|---:|---|---|---|",
    ]
    for r in data["tools"]:
        status = "✅ installed" if r["installed"] else "❌ missing"
        found = ", ".join(r["found_commands"] + r["found_python_modules"]) or "-"
        lines.append(f"| {status} | {r['name']} | {r['stars']} | {r['purpose']} | {found} | {r['repo']} |")
    lines += ["", "## Recommended missing tools", ""]
    if data["recommended_missing"]:
        for i, r in enumerate(data["recommended_missing"], 1):
            lines.append(f"{i}. **{r['name']}** ({r['stars']} stars): {r['purpose']} → {r['repo']}")
    else:
        lines.append("All recommended tools for this profile are installed.")
    lines += ["", "## Next step", "Run artifact triage first, then install only the missing tools needed for the selected profile.", ""]

    # ========== PROFILE-SPECIFIC GUIDANCE ==========
    profile = data["profile"]
    if profile == "game":
        lines += [
            "",
            "### Game Reversing Profile Guidance",
            "",
            "1. Use Cheat Engine for pointer-chain discovery and memory scanning",
            "2. Use ReClass.NET for memory structure layout reconstruction",
            "3. Use Frida for dynamic instrumentation on Android game targets",
            "4. Use Ghidra/radare2 for static analysis of game binaries (libil2cpp.so, GameAssembly.dll)",
            "",
        ]
    elif profile == "android-kernel":
        lines += [
            "",
            "### Android Kernel Profile Guidance",
            "",
            "1. Use Ghidra/radare2 for .ko static analysis (ioctl dispatch, file_operations)",
            "2. Use Frida/objection for runtime exploration on rooted device",
            "3. Use NDK (clang++, ndk-build) for building test harnesses",
            "4. Use Magisk for root/hiding and module deployment on device",
            "",
        ]
    elif profile == "code-gen":
        lines += [
            "",
            "### Code Generation Profile Guidance",
            "",
            "1. Ensure NDK toolchain is available (clang++, ndk-build, Android.mk)",
            "2. Use Ghidra/radare2 for evidence extraction (offsets, structures)",
            "3. Use jadx for hybrid Java/native analysis if target is Android",
            "4. For on-device compilation, install AIDE on the Android test device",
            "",
        ]
    elif profile == "web":
        lines += [
            "",
            "### Web Penetration Testing Profile Guidance",
            "",
            "1. Confirm target is whitelisted before active scanning.",
            "2. Use ffuf/gobuster for directory discovery.",
            "3. Use sqlmap (safe mode) and dalfox for injection detection.",
            "4. Use mitmproxy for intercepting and modifying HTTP traffic.",
            "",
        ]
    elif profile == "network":
        lines += [
            "",
            "### Network Protocol Reversing Profile Guidance",
            "",
            "1. Capture traffic with Wireshark/tcpdump.",
            "2. Use mitmproxy for HTTP/HTTPS interception.",
            "3. Use Scapy for custom packet crafting and replay.",
            "4. Use hydra for password brute-forcing on network protocols.",
            "",
        ]

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit local high-value reverse-engineering tools")
    parser.add_argument("--profile", default="auto", 
                        choices=["auto","triage","native","android","mobile","firmware","dynamic",
                                 "windows","vuln","fuzzing","memory","emulation","kernel","malware",
                                 "game","android-kernel","code-gen","network","web"],
                        help="Tool profile to check")
    parser.add_argument("--out", help="Optional output path (.json or .md)")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown")
    args = parser.parse_args()
    data = audit(args.profile)
    rendered = json.dumps(data, indent=2, ensure_ascii=False) if args.json else to_markdown(data)
    if args.out:
        out = Path(args.out).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(out)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())