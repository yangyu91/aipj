# Tooling Matrix

Select tools already available in the environment. Do not install heavy tooling unless useful and permitted.

## Universal triage
- Hashes: `Get-FileHash`, `sha256sum`, Python `hashlib`
- File type: `file`, Python magic-bytes fallback
- Strings: `strings`, FLOSS, Python fallback
- Metadata: ExifTool, Detect It Easy, TrID
- Hex view: `xxd`, `hexdump`, HxD, 010 Editor

## Game memory reversing
- Pointer-chain discovery: Cheat Engine (memory scan, pointer scan, dissect data/structures)
- Memory structure reverse: ReClass.NET (layout reconstruction, offset mapping)
- Dynamic confirmation: Frida (Dobby/Inline hook, memory read/write), x64dbg (Windows game clients), GDB (Linux game clients)
- View-matrix extraction: Ghidra/radare2 (static analysis of rendering functions), Cheat Engine (live matrix search)
- Offsets validation: freeze/modify/observe workflow, memory region analysis (readable/writable/executable permissions)

**Evidence to collect per game target:**
- Process name, PID, module base address (from `/proc/[pid]/maps` or Cheat Engine)
- Offset chain (base → offset1 → offset2 → ... → field), data type (float/int/vec3/vec4), validation method (freeze/modify/observe)
- Screenshot of Cheat Engine scan results, ReClass.NET structure view, or debugger memory dump

## Native binary static analysis
- Ghidra, IDA Free/Pro, Binary Ninja, Radare2/rizin, objdump, readelf, nm, dumpbin
- PE: PE-bear, CFF Explorer, pefile, sigcheck
- ELF: readelf, checksec, ldd only in safe contexts, eu-readelf
- Mach-O: otool, jtool2, class-dump/objc tools

## Dynamic analysis
- Debuggers: x64dbg, WinDbg, gdb/lldb, Frida
- Tracing: Procmon, Process Explorer, API Monitor, strace/ltrace, dtruss, ETW/xperf
- Network: Wireshark, tcpdump, mitmproxy in authorized lab
- Sandboxes: local VM snapshots, containers for Linux utilities, emulator for mobile

## Managed/mobile
- .NET: dnSpyEx, ILSpy, dotnet metadata tools
- Java/Android: jadx, apktool, dex2jar, Android Studio profiler, adb
- iOS/macOS: class-dump, Hopper/Ghidra, lldb, Frida on owned test devices
- Android cheat/assist: Magisk (root/hiding/module management), Objection (runtime exploration), Frida (dynamic instrumentation with custom scripts, memory read/write, anti-anti-debug)
- Kernel module analysis: Ghidra/radare2 (`.ko` static analysis, ioctl command extraction), adb (module deployment, log collection)
- Environment validation: `lsmod` (loaded modules), `uname -r` (kernel version), `getenforce` (SELinux status), `cat /proc/cmdline` (KASLR detection)
**Evidence to collect per Android kernel target:**
- Kernel version, module load address (from `/proc/modules`), ioctl command codes (from Ghidra/IDA), syscall wrapper logs
- SELinux context, KASLR status, test device model/OS version

## Firmware
- binwalk, unblob, jefferson/sasquatch, unsquashfs, qemu-user/system, FirmAE when appropriate

## Vulnerability evidence
- Sanitizers: ASAN/UBSAN/MSAN where recompilation is possible
- Fuzzing harness support: libFuzzer/AFL++/honggfuzz for owned code or lab targets
- Crash triage: debugger stack trace, registers, fault address, input offset correlation
- Patch diff: bindiff, Diaphora, Ghidra version tracking, git diff/source diff

## Evidence to collect per tool run
Record command, version, input hash, output path, timestamp, and interpretation. Prefer raw logs plus a short summarized finding.
- For game targets: process name, module base, offset chain, data type, validation method, Cheat Engine screenshot.
- For Android kernel targets: kernel version, .ko load address, ioctl command codes, syscall wrapper logs.
- For code generation: file tree, source files, build command, binary path, push/run commands.

## Code generation (C++/AIDE/NDK)
- C++ compiler toolchain: NDK (clang++, ndk-build, Android.mk, Application.mk) - https://developer.android.com/ndk
- On-device compilation: AIDE (Android IDE) - on-device build environment for generated source files
- Source generation: offsets.h, memory.cpp, main.cpp, hooks.cpp, utils.cpp
- Build delivery: `ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./jni/Android.mk`
- Output validation: `adb push`, `chmod +x`, `adb shell ./binary`

**Evidence to collect per code generation run:**
- Project file tree (jni/ directory listing)
- Generated source files (full content with evidence comments)
- Build command and output (success/failure, binary path, size)
- Deploy/run commands and validation logs

## Web penetration testing matrix
| Task | Tools | Evidence |
|---|---|---|
| Reconnaissance | dig, curl, WhatWeb | DNS records, HTTP headers |
| Tech Stack ID | Wappalyzer, auto_pentest.py | Fingerprint logs, version info |
| Dir Busting | ffuf, gobuster | 200 OK paths, admin URLs |
| SQL Injection | sqlmap, manual payloads | Boolean-blind proof, DB version |
| XSS Scanning | dalfox, manual payloads | Alert execution, unescaped output |
| Auth Brute | hydra, ffuf | Valid credentials, session token |

## Network protocol reversing matrix
| Task | Tools | Evidence |
|---|---|---|
| Traffic Capture | Wireshark, tcpdump | PCAP files, stream logs |
| MITM | mitmproxy, Burp Suite | Intercepted traffic, modified requests |
| Protocol Analysis | Ghidra, radare2, Scapy | Message structure, framing rules |
| Replay Testing | Scapy, custom scripts | Successful retransmission, server response |
| Crypto Review | CyberChef, Python crypto | Decrypted payloads, key extraction |

