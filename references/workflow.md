# Reverse Flow Workflow

## Phase gates

### 0. Scope gate
Proceed when the artifact, goal, and permitted environment are known. If scope is unclear, state the assumption and continue with offline, non-invasive analysis.

### 1. Intake deliverables
- Case ID and workspace path
- Artifact inventory with SHA-256, SHA-1, MD5, size, path, source notes
- Scope and constraints
- Initial questions or assumptions

### 2. Analysis deliverables
- File type, architecture, compiler/runtime hints, timestamps, signatures, packer/obfuscation indicators
- Strings/configs/imports/exports/symbols/resources
- Dependency and execution requirements
- Initial behavior hypotheses with evidence

### 3. Initial report deliverables
- Executive summary
- Evidence table
- Risk summary
- Unknowns and blocked areas
- Next-step menu

### 4. Reverse deliverables
- Function/module map
- Entry points and interesting call graph slices
- Data structures, file formats, protocols, IPC, registry/filesystem/network touchpoints
- Dynamic traces when available

### 5. Deep reverse deliverables
- Decompiled pseudocode explanations
- State machines and algorithms
- Data-flow and trust-boundary analysis
- Patch diff or version comparison when applicable
- Validated behavior model

### 6. Vulnerability review deliverables
- Candidate weakness list
- Root cause and reachability
- Preconditions and affected surface
- Safe reproduction evidence such as crash trace, sanitizer output, unit harness, or packet/file sample description
- Severity rationale and remediation

## Specialized deliverables for game/Android/code-gen

### Game memory reversing (in addition to generic deliverables)
- **Intake/Scope**: target process name, game version, platform (Android/Windows/Linux), module name (e.g., libil2cpp.so, GameAssembly.dll)
- **Analysis**: memory regions (maps), module base address, pointer-chain discovery results, data type identification (float/int/vec3)
- **Reverse**: validated offset chain (base → offset1 → offset2 → field), view-matrix location, entity list structure
- **Vulnerability review**: pointer-chain staleness risk, write-side effects, anti-cheat detection vectors

### Android kernel module reversing (in addition to generic deliverables)
- **Intake/Scope**: kernel version, device model/OS version, .ko filename, load/unload commands
- **Analysis**: /proc/modules output, module load address, SELinux context, KASLR status
- **Reverse**: module_init/module_exit, file_operations mapping, ioctl command codes, syscall hook points
- **Vulnerability review**: ioctl permission bypass, module load races, info leaks, syscall table instability

### Code generation (C++/AIDE/NDK) (final delivery phase)
- **Intake/Scope**: confirmed offsets and evidence mapping, target platform ABI (armeabi-v7a/arm64-v8a/x86_64)
- **Analysis**: NDK toolchain availability, AIDE environment check, build constraints
- **Reverse-to-code mapping**: each offset → source file → function, with evidence trace
- **Delivery**: complete jni/ project structure, Android.mk, Application.mk, full source files, ndk-build command, deploy/run instructions, online risk warning

### Web penetration testing (authorized whitelisted targets)
- **Intake/Scope**: target URL/IP, authorization confirmation, scope boundaries
- **Analysis**: technology stack identified, CVE matches, passive recon findings
- **Reverse**: active test results (dir busting, SQLi, XSS), payload evidence
- **Delivery**: comprehensive pentest report, remediation guidance, risk scoring

### Network protocol reversing
- **Intake/Scope**: protocol type, PCAP files, client binary, network environment
- **Analysis**: message framing, serialization patterns, encryption detection
- **Reverse**: state machine map, recovered message structures, state transitions
- **Delivery**: protocol reverse engineering report, vulnerability candidates, replay PoC

## User-selectable next-step menu

Offer options tailored to evidence. Typical menu:

1. Continue static reverse of the highest-risk function/module.
2. Run or design dynamic tracing in an isolated lab.
3. Build a data-flow map for inputs crossing trust boundaries.
4. Perform vulnerability-focused review and root-cause analysis.
5. Produce a concise report/advisory for sharing.
6. Stop and summarize current findings.

## Escalation criteria

Move to deep reverse when any condition holds:
- Initial analysis identifies packed/obfuscated code, custom crypto/encoding, undocumented protocol, suspicious persistence, or high-risk parser.
- A crash, sanitizer finding, or suspicious bounds/state bug is observed.
- The user asks for root cause, affected versions, remediation, or vendor-style disclosure material.

### Game-specific escalation
- Pointer-chain validation fails (offset no longer resolves to valid address) → escalate to dynamic scanning fallback or signature-based rediscovery.
- Game update detected (module size/version changed) → escalate to re-analysis of offsets and entity structures.

### Android kernel-specific escalation
- Kernel module shows `ioctl` handlers without capability checks → escalate to vulnerability review.
- `sys_call_table` modification detected without proper synchronization → escalate to stability/panic risk assessment.

### Code-generation-specific escalation
- Missing critical offsets (player array not found, view-matrix not located) → escalate to signature-scanning stub generation.
- NDK build fails due to missing toolchain or incorrect `Android.mk` → escalate to environment audit and remediation.

### Web-pentest-specific escalation
- High-risk tech stack identified (e.g., outdated WordPress) → escalate to targeted CVE matching and exploitation attempts.
- Critical vulnerability found (e.g., SQLi) → escalate to full data-flow analysis and risk assessment.

### Network-reversing-specific escalation
- Custom encryption detected → escalate to crypto analysis and key extraction.
- Replay attack successful → escalate to session handling and replay protection review.

### User-requested escalation
- User asks for "root cause", "affected versions", "remediation", "patch diff", or "vulnerability advisory" → escalate from Reverse or Deep Reverse to Vulnerability Review.
- User asks for "generate code", "output cpp", "create AIDE project", or "build the cheat tool" → escalate to Code Generation phase.
- User provides "白名单" (whitelist) directive → escalate to Automated Web Penetration Testing Workflow.