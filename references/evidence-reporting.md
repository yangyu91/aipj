# Evidence and Reporting

## Initial report template
### 专项补充（游戏/安卓/代码生成时必填） / Specialized fields (mandatory for game/Android/code-gen targets)

**For game targets:**
- Target process name: ________
- Module base address: ________ (hex)
- Offset chain: ________ → ________ → ________
- Data type: float / int / vec3 / other
- Validation method: freeze / modify / observe / other

**For Android kernel targets:**
- Kernel version: ________
- .ko load address (from /proc/modules): ________
- ioctl command codes: ________ (list with hex values)
- Syscall wrapper logs: ________ (attach excerpt)

**For code generation output:**
- Evidence-to-code mapping table: (list each offset → source file → function)
- Full file tree: (list jni/ directory structure)
- ndk-build command: ________
- Expected output binary path: ________
- Push/run commands: adb push ... && chmod +x ... && ./...
- Online risk warning: Explicitly state "For offline lab use only" and list detection vectors.

```markdown
# Reverse Engineering Initial Report

## Summary
- Artifact:
- Scope:
- Current phase:
- Overall risk:

## Artifact inventory
| Name | Path | Size | SHA-256 | Type | Notes |
|---|---|---:|---|---|---|

## Verified facts
| ID | Evidence | Source/offset/tool | Interpretation | Confidence |
|---|---|---|---|---|

## Key findings
### Finding 1: <title>
- Evidence:
- Impact:
- Confidence:
- Validation status:

## Unknowns
- 

## Recommended next steps
1. 
2. 
3. 
```

## Deep reverse report template

```markdown
# Deep Reverse Engineering Report

## Executive summary
## Scope and artifacts
## Methodology
## Architecture and behavior model
## Function/module map
## Data-flow and trust boundaries
## Dynamic observations
## Vulnerability candidates
## Evidence appendix
## Reproducibility notes
## Recommended next steps
```

## Vulnerability advisory template

```markdown
# Vulnerability Report: <title>

## Summary
## Affected product/version/component
## Severity and rationale
## Preconditions
## Root cause
## Technical details
## Safe reproduction evidence
## Impact
## Remediation guidance
## Detection/mitigation
## Evidence appendix
## Timeline/status
```

## Confidence vocabulary
- **High**: directly observed in code or runtime and reproducible.
- **Medium**: supported by multiple static indicators but not fully executed.
- **Low**: plausible hypothesis with limited evidence.

## Evidence table rules
Use stable identifiers. Include offsets, function names, command outputs, hashes, log excerpts, screenshots, or traces. Keep raw logs in the case directory and summarize only the relevant lines in reports.
- For game/Android/code-gen reports, every offset must be accompanied by: source artifact (process/module name), derivation method (Ghidra/Cheat Engine/dynamic scan), and verification step (freeze/modify/observe change). For code generation, each constant in `offsets.h` must trace back to a specific evidence row in this table.

## Code generation delivery report template

Use this template when the user requests a complete C++ AIDE/NDK project based on reversed evidence.

### Template body

```markdown
# C++ AIDE Project Code Generation Report

## Current phase
Code generation (final delivery)

## Evidence-to-code mapping
| Offset/constant | Source evidence (file/offset/tool) | Destination source file | Function name |
|-----------------|-------------------------------------|-------------------------|---------------|
| 0x1234 | libil2cpp.so @ 0x1234 via Ghidra | offsets.h | kPlayerBaseOffset |
| ... | ... | ... | ... |

## Project file tree
```

jni/
├── Android.mk
├── Application.mk
├── main.cpp
├── memory.cpp
├── memory.h
├── offsets.h
├── hooks.cpp (if applicable)
├── hooks.h
├── utils.cpp
└── utils.h

```

## Full source code
### jni/offsets.h
```cpp
// All offsets derived from reverse analysis
static constexpr uintptr_t kPlayerBaseOffset = 0x1234; // Ghidra: libil2cpp.so @ 0x1234
// ... add other offsets
```

jni/memory.h

```cpp
// Read/write primitives declarations
```

jni/memory.cpp

```cpp
// Implement process_vm_readv/writev, /proc/pid/mem fallback, etc.
```

jni/main.cpp

```cpp
// Entry point, main loop, feature calls
```

jni/Android.mk

```makefile
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := cheat_core
LOCAL_SRC_FILES := main.cpp memory.cpp utils.cpp hooks.cpp
LOCAL_LDLIBS := -llog -lz
include $(BUILD_EXECUTABLE)
```

jni/Application.mk

```makefile
APP_ABI := armeabi-v7a arm64-v8a x86_64
APP_PLATFORM := android-21
APP_STL := c++_static
```

Build instructions

```bash
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./jni/Android.mk
```

Expected output: libs/arm64-v8a/cheat_core

Deploy and run

```bash
adb push libs/arm64-v8a/cheat_core /data/local/tmp/
adb shell chmod +x /data/local/tmp/cheat_core
adb shell /data/local/tmp/cheat_core
```

⚠️ Online risk warning

This binary is for offline lab use only. The following detection vectors may trigger anti-cheat in online environments:

· Syscall signature (process_vm_readv/writev patterns)
· /proc/[pid]/mem file access
· Module base scanning heuristics
· File path /data/local/tmp/ access

Recommended next steps

1. Compile and test in local emulator
2. Verify all offsets with dynamic scan
3. Add signature-scanning fallback for missing offsets
4. Generate updated report after validation
