# Curated Reverse Tool Catalog

Snapshot: GitHub star counts queried on 2026-07-01. Stars are approximate and should be refreshed before publication claims.

## High-star tools by purpose

| Tool | Repo | Stars | Best for | Local command hints |
|---|---|---:|---|---|
| Ghidra | https://github.com/NationalSecurityAgency/ghidra | 70,306 | native decompilation, SRE projects | `ghidraRun`, `analyzeHeadless` |
| jadx | https://github.com/skylot/jadx | 49,250 | Android DEX/APK decompilation | `jadx`, `jadx-gui` |
| x64dbg | https://github.com/x64dbg/x64dbg | 48,770 | Windows user-mode debugging | `x64dbg`, `x32dbg` |
| hashcat | https://github.com/hashcat/hashcat | 26,241 | offline hash recovery in authorized cases | `hashcat` |
| Apktool | https://github.com/iBotPeaches/Apktool | 24,904 | APK resources/smali decode/rebuild | `apktool` |
| radare2 | https://github.com/radareorg/radare2 | 24,225 | CLI disassembly, scripting, triage | `r2`, `rabin2`, `rahash2` |
| Frida | https://github.com/frida/frida | 21,168 | dynamic instrumentation | `frida`, `frida-trace` |
| Binwalk | https://github.com/ReFirmLabs/binwalk | 14,083 | firmware carving/extraction | `binwalk` |
| John the Ripper | https://github.com/openwall/john | 13,318 | offline password/hash auditing | `john` |
| Google Sanitizers | https://github.com/google/sanitizers | 12,407 | sanitizer-backed crash/root-cause validation | compiler flags |
| OSS-Fuzz | https://github.com/google/oss-fuzz | 12,398 | continuous fuzzing patterns | templates |
| Detect It Easy | https://github.com/horsicq/Detect-It-Easy | 11,062 | file/compiler/packer identification | `diec`, `die` |
| pwndbg | https://github.com/pwndbg/pwndbg | 10,609 | GDB reverse/debug UX | `gdb` plugin |
| YARA | https://github.com/VirusTotal/yara | 9,721 | rule-based pattern matching | `yara` |
| Unicorn | https://github.com/unicorn-engine/unicorn | 9,126 | CPU emulation | Python module |
| angr | https://github.com/angr/angr | 8,921 | symbolic execution and CFG analysis | Python module |
| FLARE-VM | https://github.com/mandiant/flare-vm | 8,809 | Windows RE lab provisioning | PowerShell installer |
| Capstone | https://github.com/capstone-engine/capstone | 8,872 | disassembly library | Python module / library |
| RetDec | https://github.com/avast/retdec | 8,566 | machine-code decompilation | `retdec-decompiler` |
| GEF | https://github.com/hugsy/gef | 8,251 | GDB enhancement | `gdb` plugin |
| AFL++ | https://github.com/AFLplusplus/AFLplusplus | 6,628 | coverage-guided fuzzing | `afl-fuzz` |
| syzkaller | https://github.com/google/syzkaller | 6,249 | kernel fuzzing | `syz-manager` |
| PEDA | https://github.com/longld/peda | 6,130 | GDB exploit/reverse assistance | `gdb` plugin |
| capa | https://github.com/mandiant/capa | 6,080 | capability detection in executables | `capa` |
| Qiling | https://github.com/qilingframework/qiling | 5,986 | instrumentable binary emulation | Python module |
| LIEF | https://github.com/lief-project/LIEF | 5,460 | executable format parsing/modification | Python module |
| Bloaty | https://github.com/google/bloaty | 5,496 | binary size/profiling | `bloaty` |
| Volatility 3 | https://github.com/volatilityfoundation/volatility3 | 4,223 | memory forensics | `vol`, `vol.py` |
| FLOSS | https://github.com/mandiant/flare-floss | 4,066 | obfuscated string extraction | `floss` |
| Manticore | https://github.com/trailofbits/manticore | 3,857 | symbolic execution | `manticore` |
| Rizin | https://github.com/rizinorg/rizin | 3,693 | CLI disassembly/reverse framework | `rizin`, `rz-bin` |
| Cheat Engine | https://github.com/cheat-engine/cheat-engine | 17,893 | game memory scanning, pointer-chain discovery | `cheatengine-x86_64` |
| ReClass.NET | https://github.com/ReClassNET/ReClassNET | 4,224 | game memory structure reverse engineering | `ReClass.NET.exe` |
| Frida | https://github.com/frida/frida | 21,168 | Android dynamic instrumentation (already listed) | `frida`, `frida-ps`, `frida-trace` |
| Magisk | https://github.com/topjohnwu/Magisk | 55,221 | Android root/hiding and module management | `magisk` (on device) |
| Objection | https://github.com/sensepost/objection | 7,508 | Android/iOS runtime exploration | `objection` |
| NDK | https://developer.android.com/ndk | - | Android C++ compilation toolchain | `ndk-build`, `clang++` |
| AIDE | https://aide.en.softonic.com/android | - | on-device Android C++ IDE/build | AIDE app (on device) |

## Profile mapping

- **native**: Ghidra, radare2/Rizin, Detect It Easy, capa, FLOSS, YARA, x64dbg, GDB + pwndbg/GEF, Capstone, LIEF.
- **android**: jadx, Apktool, Frida, Ghidra for native libs, adb if available.
- **firmware**: Binwalk, unblob if installed, Ghidra, Qiling/Unicorn, YARA, strings, file.
- **dynamic**: x64dbg, WinDbg, GDB, lldb, Frida, Procmon/strace/tcpdump/Wireshark where available.
- **vulnerability**: AFL++, sanitizers, syzkaller for kernels, Ghidra, debuggers, crash triage tools.
- **memory**: Volatility 3, YARA, strings, timeline tooling.
- **game**: Cheat Engine, ReClass.NET, Ghidra, radare2, Frida, x64dbg (for Windows game clients), GDB (for Linux game clients).
- **android-kernel**: Ghidra (kernel module support), radare2, Frida (with kernel scripts), Magisk, Objection, adb, ndk-build (for test harnesses).
- **code-gen**: NDK toolchain (clang++, ndk-build), AIDE (on-device), Ghidra (evidence extraction), jadx (for hybrid Java/native analysis).
- **web**: ffuf, sqlmap, gobuster, dalfox, hydra, mitmproxy, Wireshark, Burp Suite.
- **network**: Wireshark, tcpdump, mitmproxy, Scapy, hydra, boofuzz, CyberChef.

## Selection rule

Start with the smallest local toolchain that answers the user's question. Do not require every tool. Prefer installed tools, then suggest missing tools as optional next steps.
- For game targets: prioritize Cheat Engine for pointer-chain discovery, then validate offsets with Ghidra/radare2 static analysis, then use Frida or x64dbg for dynamic confirmation.
- For Android kernel modules: use Ghidra for .ko static analysis, radare2 for CLI triage, adb for deployment, and ndk-build for building test harnesses.
- For code generation: ensure NDK toolchain is available (clang++, ndk-build, Android.mk). If on-device compilation is requested, suggest AIDE with the generated source files.
- For web targets: confirm whitelisted authorization, then use ffuf/gobuster for discovery, then sqlmap/dalfox for vulnerability scanning.
- For network protocols: capture traffic with Wireshark/tcpdump, analyze with Ghidra/radare2, and test with Scapy/mitmproxy.
