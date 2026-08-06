# Capability Checklist

Use this checklist to avoid missing common reverse-engineering skills.

## Universal skills
- Evidence preservation, hashing, chain-of-custody notes
- File identification, entropy, metadata, signatures, timestamps
- Strings extraction: ASCII, UTF-16LE, high-entropy config blobs, URLs, paths, registry keys, mutexes, user agents, error messages
- Symbol/import/export/resource analysis
- Control-flow and data-flow mapping
- Hypothesis tracking and confidence scoring
- Report writing with reproducible evidence

## Native binaries
- PE/ELF/Mach-O headers, sections/segments, relocations, symbols
- Architecture and ABI identification: x86/x64/ARM/MIPS/RISC-V
- Compiler/runtime fingerprints: MSVC, GCC/Clang, Go, Rust, Delphi, Nim
- Disassembly/decompilation navigation, xrefs, call graph, vtables, RTTI
- Debugging, tracing, memory maps, breakpoints/watchpoints
- Packers/obfuscators: entropy, import resolution, unpacking strategy, anti-debug indicators
- Android native ELF/SO specifics: JNI export/RegisterNatives, init/init_array/fini, dynamic linker behavior, TracerPid/ptrace anti-debug, timing traps
- Linux kernel module (LKM) reversing: ioctl command dispatch, copy_from_user/copy_to_user structures, syscall table hijacking (sys_call_table), kprobes/ftrace hooks, netfilter hooks
- Kernel environment evidence: /proc/modules load addresses, kernel version/fingerprint (GKI/vendor), sepolicy/selinux context, KASLR state

## Managed and script runtimes
- .NET metadata, IL, assemblies, resources, deobfuscation indicators
- JVM bytecode, Android DEX/APK, manifests, permissions, native libraries
- Python/Node/PowerShell/Lua scripts, packed bytecode, dependency manifests

## Firmware and embedded
- Container extraction, filesystem carving, bootloader/kernel/rootfs layout
- CPU/SoC identification, endianness, memory maps
- Init scripts, services, web endpoints, hardcoded credentials, update mechanism
- Emulation or targeted static review when execution is impractical

## Mobile
- APK/IPA structure, manifests/entitlements, permissions, URL schemes
- Network endpoints, certificate pinning indicators, local storage, secrets
- Native bridges and JNI/Swift/Obj-C boundaries
- Android cheat/assist primitives: process_vm_readv/writev, /proc/[pid]/mem access, /dev/mem/kmem (root), IOCTL-based kernel R/W channels
- Injection strategies: ptrace remote injection, zygote preload, LD_PRELOAD, LKM-based code injection
- Hiding/evasion: process name spoofing, file path hiding (faccessat/fstat hooks), magisk module overlay, sepolicy patching
- Memory scanning: pointer-chain derivation (base + offsets), dynamic heap/object address tracking, freeze/modify/observe validation

## Game reversing
- Game memory archetypes: health, ammo, position, view-angles, coordinates, player entity lists, team IDs
- Pointer-chain scanning: static base + offsets vs dynamic heap addresses, multi-level pointer dereference validation
- Rendering/graphics hooks: DirectX 11/12, OpenGL, Vulkan matrix transformations, view-projection matrix location, overlay drawing (ESP boxes, radar, health bars)
- Anti-cheat local analysis: simulated VAC/EAC/BattleEye hooks, integrity CRC checks, obfuscated imports, syscall/API hook detection
- Recoil/spread mechanics: weapon impulse functions, zero-delta patch points, fire rate modification
- Evidence binding: process name, module base, offset chain, data type (float/int/vec3), validation method (freeze/modify/observe)

## Documents and parsers
- File format validation, embedded objects/macros/scripts
- Parser attack surface, decompression/archive nesting, malformed field handling
- Safe sandboxing and metadata extraction before opening in GUI tools

## Web penetration testing
- Passive reconnaissance: DNS, headers, TLS/SSL, robots.txt, sitemap.xml
- Technology fingerprinting: server, framework, CMS, language, frontend libraries
- CVE auto-matching: version identification and NVD/local database querying
- Active testing: directory/file bruteforcing, parameter discovery, SQL injection, XSS, authentication brute-force
- API security: endpoint enumeration, REST/GraphQL/SOAP analysis, authz/authn testing

## Network protocol reversing
- Traffic capture: tcpdump, Wireshark, mitmproxy
- Protocol analysis: message framing, delimiters, endianness, serialization (Protobuf, JSON, Binary)
- State machine recovery: INIT, AUTH, READY, DISCONNECT transitions
- Vulnerability testing: replay attacks, session hijacking, downgrade attacks, crypto weaknesses
- Man-in-the-middle: certificate pinning bypass, traffic interception and modification

## Vulnerability-focused skills
- Input surface mapping
- Trust-boundary identification
- Bounds, integer, lifetime, format-string, injection, deserialization, authz/authn, crypto misuse, insecure update/storage checks
- Crash triage and root cause
- Patch diffing and regression tests
- Severity, remediation, and disclosure-ready reporting

## Reverse-to-code generation (C++/AIDE/NDK)
- Project scaffolding: jni/ directory, Android.mk (LOCAL_MODULE, LOCAL_SRC_FILES, LOCAL_LDLIBS), Application.mk (APP_ABI, APP_PLATFORM, APP_STL)
- Offsets to constants: all derived offsets as static constexpr uintptr_t in offsets.h with evidence comments (source file + offset + tool used)
- Base address resolution: get_module_base(pid, name) via /proc/[pid]/maps parsing
- Read/write primitives implementation: process_vm_readv/writev (primary), /proc/[pid]/mem + lseek64 (fallback), IOCTL wrappers (kernel-level)
- Error handling: errno checks, retry logic, boundary validation, crash avoidance
- Feature translation: ESP, aimbot, no-recoil, teleport, triggerbot → standalone C++ functions using pointer-chain and primitives
- Build delivery: ndk-build command, output binary path (libs/ABI/cheat_core), adb push + chmod + run instructions
- Stub generation: signature-scanning fallback for missing offsets, TODO comments for dynamic discovery