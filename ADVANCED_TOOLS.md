# Advanced Tools Reference

This document covers the advanced, kernel, hardware, forensics, and specialized architecture tools that extend beyond the core reference in [docs/REFERENCE.md](docs/REFERENCE.md).

## Table of Contents

1. [Advanced Exploit Development](#advanced-exploit-development)
2. [Hardware Tracing & CET](#hardware-tracing--cet)
3. [Deep Forensics & Kernel Internals](#deep-forensics--kernel-internals)
4. [Specialized Architecture & Virtualization](#specialized-architecture--virtualization)
5. [Malware Analysis & Unpacking (Extended)](#malware-analysis--unpacking-extended)
6. [Anti-Debug, Anti-Analysis & Evasion](#anti-debug-anti-analysis--evasion)
7. [Binary Intelligence & Triage](#binary-intelligence--triage)
8. [Injection, Persistence & C2](#injection-persistence--c2)
9. [Coverage, Watch & Automation](#coverage-watch--automation)
10. [Usage Examples: Top 20 Advanced Tools](#usage-examples-top-20-advanced-tools)

---

## Advanced Exploit Development

### `x64dbg_rop_builder`

Advanced ROP chain construction and analysis.

| Action | Parameters | Description |
|--------|------------|-------------|
| `find_gadgets` | `effect`, `module?`, `max_results?` | Search for gadgets by desired effect |
| `build_chain` | `gadgets[]`, `target?` | Construct ROP chain from gadget list |
| `validate_chain` | `chain_address`, `chain_length?` | Validate chain in memory |
| `export_chain` | `gadgets[]`, `format?`, `include_args?` | Export as asm/c/python/c_shellcode |

**Example: Find gadgets for "pop rcx; ret"**
```json
{
  "tool": "x64dbg_rop_builder",
  "arguments": {
    "action": "find_gadgets",
    "effect": "pop rcx; ret",
    "module": "ntdll.dll",
    "max_results": 10
  }
}
```

**Example: Build and validate a chain**
```json
{
  "tool": "x64dbg_rop_builder",
  "arguments": {
    "action": "build_chain",
    "gadgets": [
      {"address": "0x401000", "purpose": "load /bin/sh", "args": {"rcx": "0x402000"}},
      {"address": "0x401020", "purpose": "call system", "args": {}}
    ],
    "target": "execute_shellcode"
  }
}
```

### `x64dbg_gadget_semantic_builder`

Constraint-based semantic gadget synthesis.

### `x64dbg_heap_gadget_finder`

Segment heap & NT heap exploitation primitives.

### `x64dbg_symbolic_exploit_finder`

SMT constraint-guided crash path exploration.

### `x64dbg_exploit_likelihood_scorer`

Composite exploitability probability scoring.

### `x64dbg_vuln_chain_discoverer`

Multi-stage exploit chain synthesis.

### `x64dbg_api_dependency_graph`

API call dependency mapping.

### `x64dbg_string_decryption_automation`

Automated multi-algorithm string decryption.

### `x64dbg_jit_rop_analyzer`

JIT ROP gadget analysis.

### `x64dbg_gadget_quality_scorer`

Gadget reliability scoring.

### `x64dbg_semantic_patcher`

Intent-based patching.

---

## Hardware Tracing & CET

### `x64dbg_intel_pt_tracer`

Intel Processor Trace hardware execution decoder and AFL++ coverage bitmap exporter.

| Action | Parameters | Description |
|--------|------------|-------------|
| `status` | — | Check Intel PT status |
| `decode_trace` | — | Decode raw Intel PT packets |
| `export_coverage_bitmap` | — | Export AFL++ coverage bitmap |

**Example: Check Intel PT status**
```json
{
  "tool": "x64dbg_intel_pt_tracer",
  "arguments": {
    "action": "status"
  }
}
```

**Example: Decode trace and export coverage**
```json
{
  "tool": "x64dbg_intel_pt_tracer",
  "arguments": {
    "action": "decode_trace"
  }
}
```

### `x64dbg_cet_shadow_stack_manipulator`

Intel CET shadow stack, RSTORSSP tokens, and Indirect Branch Tracking (IBT) validator.

| Action | Parameters | Description |
|--------|------------|-------------|
| `read_shadow_stack` | — | Dump shadow stack contents |
| `audit_ssp_tokens` | — | Validate SSP token integrity |
| `scan_endbr_violations` | `start_address?`, `size?` | Scan for missing ENDBRANCH markers |

**Example: Scan for ENDBR violations**
```json
{
  "tool": "x64dbg_cet_shadow_stack_manipulator",
  "arguments": {
    "action": "scan_endbr_violations",
    "start_address": "0x140000000",
    "size": 0x10000
  }
}
```

### `x64dbg_speculative_gadget_hunter`

Speculative execution gadget discovery.

### `x64dbg_xsave_avx512_inspector`

XSAVE/AVX-512 state inspector.

### `x64dbg_lbr_branch_ring_inspector`

LBR branch ring inspector.

### `x64dbg_amx_matrix_inspector`

AMX matrix inspector.

---

## Deep Forensics & Kernel Internals

### `x64dbg_mmvad_tree_explorer`

MMVAD tree explorer for VAD-based forensics.

### `x64dbg_kernel_pool_feng_shui`

Kernel pool layout analysis and chunk grooming.

### `x64dbg_lsass_dpapi_blob_reader`

LSASS DPAPI blob reader.

### `x64dbg_ntfs_mft_artifact_carver`

NTFS MFT artifact carver.

### `x64dbg_kernel_callback_auditor`

Kernel callback enumeration and integrity check.

### `x64dbg_kernel_structures`

Kernel structure inspector: KTHREAD/KPCR/Object Types/DKOM/Driver Object/Dispatch/HAL/NTFS/KUSER/Prefetch/Token/Pool/LSASS/WFP/NDIS.

### `x64dbg_hal_dispatch_hijack_auditor`

HAL dispatch hijack auditor.

### `x64dbg_wfp_callout_auditor`

WFP callout auditor.

### `x64dbg_ndis_lwf_chain_inspector`

NDIS LWF chain inspector.

### `x64dbg_prefetch_forensics_engine`

Prefetch forensics engine.

### `x64dbg_token_impersonation_chain_walker`

Token impersonation chain walker.

---

## Specialized Architecture & Virtualization

### `x64dbg_vbs_hvci_detector`

Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI), Credential Guard, and Isolated User Mode (IUM) trustlet state inspector.

| Action | Parameters | Description |
|--------|------------|-------------|
| `get_status` | — | VBS/HVCI status |
| `inspect_isolated_user_mode` | — | Inspect IUM trustlet state |
| `check_code_integrity` | — | Check code integrity policies |

**Example: Check VBS/HVCI status**
```json
{
  "tool": "x64dbg_vbs_hvci_detector",
  "arguments": {
    "action": "get_status"
  }
}
```

### `x64dbg_hypervisor_detector`

Detect and audit hypervisor environments (Hyper-V, KVM, Xen, VMware, VirtualBox) via synthetic MSRs, CPUID leaves (0x40000000+), SLDT/SIDT/SGDT instruction behaviors, and TSC timing variance.

| Action | Parameters | Description |
|--------|------------|-------------|
| `full_audit` | — | Comprehensive hypervisor audit |
| `cpuid_leaves` | — | CPUID hypervisor leaves |
| `timing_variance` | — | TSC timing variance test |
| `synthetic_msrs` | — | Synthetic MSR check |

**Example: Full hypervisor audit**
```json
{
  "tool": "x64dbg_hypervisor_detector",
  "arguments": {
    "action": "full_audit"
  }
}
```

### `x64dbg_deep_binary_virtualization`

VMX capabilities, EPT page walker, Intel PT decoder, Authenticode leaf parser, Catalog DB lookup, Security Descriptor DACL evaluator, DWARF debug parser.

### `x64dbg_specialized_architecture`

VMCS field decoder, paging walker (4-level/5-level/LA57/PCID), LoadConfig deep parser (CFG/XFG/CastGuard/CET), SMT-LIB2 solver bridge.

---

## Malware Analysis & Unpacking (Extended)

### `x64dbg_crypto_hunter`

Crypto lookup table scanner.

### `x64dbg_com_rpc_walker`

COM VTable/RPC mapper.

### `x64dbg_dotnet_helper`

CLR version detection and metadata inspection.

### `x64dbg_golang_helper`

Go runtime recovery and goroutine inspection.

### `x64dbg_rust_helper`

Rust symbol demangling.

### `x64dbg_delphi_helper`

Delphi VMT inspector.

### `x64dbg_hook_scanner`

User-mode hook scanner.

### `x64dbg_driver_auditor`

Kernel driver inspector.

### `x64dbg_ipc_monitor`

Named Pipes/Mailslots/Shared Sections monitor.

### `x64dbg_cert_authenticode`

Authenticode verification.

### `x64dbg_hotpatch_engine`

Live function hooking.

---

## Anti-Debug, Anti-Analysis & Evasion

### `x64dbg_anti_analysis_evasion`

Anti-analysis evasion techniques.

### `x64dbg_anti_anti_debug_engine`

Anti-anti-debug engine.

### `x64dbg_memory_forensics_deep`

JIT spray detection, UAF tag/analyze, memory forensics timeline, PEB LDR integrity, code signing memory validator.

| Sub-tool | Parameters | Description |
|----------|------------|-------------|
| `jit_spray_scan` | `pid?` | Detect JIT spray attacks in JIT engine memory regions |
| `jit_spray_detect_embedded` | — | Detect embedded shellcode sequences inside JIT arithmetic immediates |
| `uaf_tag_allocations` | `pid?` | Tag heap allocations with canary headers |
| `uaf_detect_stale_access` | — | Detect stale pointer access to quarantined freed heap chunks |
| `mem_timeline_reconstruct` | `pid?` | Reconstruct chronological memory allocation order |
| `peb_ldr_check_integrity` | `pid?` | Cross-check all three PEB.Ldr module lists |
| `code_sig_validate_memory` | `module_name?` | Verify in-memory .text section SHA256 against on-disk Authenticode signature |

---

## Binary Intelligence & Triage

### `x64dbg_binary_triager`

One-shot binary security triage.

### `x64dbg_code_similarity_engine`

CFG isomorphism + fuzzy hashing.

### `x64dbg_struct_reconstructor`

C/C++ struct reconstruction.

### `x64dbg_binary_analysis_deep`

Deep binary analysis tools.

### `x64dbg_legacy_debugger_tools`

Legacy debugger tools.

### `x64dbg_firmware_uefi_tools`

UEFI firmware tools.

### `x64dbg_cpu_internals_tools`

CPU internals tools.

---

## Injection, Persistence & C2

### `x64dbg_injection`

Process injection detection and analysis.

### `x64dbg_injection_persistence`

Injection persistence mechanisms.

### `x64dbg_network_c2_protocol`

Network C2 protocol analysis.

### `x64dbg_cobalt_strike_beacon`

Cobalt Strike beacon detection.

### `x64dbg_named_pipe_c2`

Named pipe C2 detection.

### `x64dbg_doh_detector`

DNS-over-HTTPS detector.

### `x64dbg_raw_socket`

Raw socket inspector.

### `x64dbg_http2_frame`

HTTP/2 frame analyzer.

### `x64dbg_protobuf_decoder`

Protocol buffer decoder.

---

## Coverage, Watch & Automation

### `x64dbg_watch`

Watch expression automation.

### `x64dbg_script_engine`

Script engine automation.

### `x64dbg_coverage`

Code coverage tools.

### `x64dbg_memwatch`

Memory watch tools.

### `x64dbg_stringxref`

String cross-reference tools.

### `x64dbg_autoannotate`

Auto-annotation tools.

### `x64dbg_calltree`

N-level call tree generator.

### `x64dbg_branch_coverage`

Branch coverage tools.

### `x64dbg_api_logger`

API call logger.

---

## Usage Examples: Top 20 Advanced Tools

### 1. ROP Chain Builder

```json
{
  "tool": "x64dbg_rop_builder",
  "arguments": {
    "action": "find_gadgets",
    "effect": "pop rdi; ret",
    "module": "kernel32.dll",
    "max_results": 5
  }
}
```

### 2. Intel PT Tracer

```json
{
  "tool": "x64dbg_intel_pt_tracer",
  "arguments": {
    "action": "status"
  }
}
```

### 3. CET Shadow Stack Manipulator

```json
{
  "tool": "x64dbg_cet_shadow_stack_manipulator",
  "arguments": {
    "action": "scan_endbr_violations",
    "start_address": "0x140000000",
    "size": 65536
  }
}
```

### 4. VBS/HVCI Detector

```json
{
  "tool": "x64dbg_vbs_hvci_detector",
  "arguments": {
    "action": "get_status"
  }
}
```

### 5. Hypervisor Detector

```json
{
  "tool": "x64dbg_hypervisor_detector",
  "arguments": {
    "action": "full_audit"
  }
}
```

### 6. Kernel Structures Inspector

```json
{
  "tool": "x64dbg_kernel_structures",
  "arguments": {
    "action": "kthread_walk_all_threads",
    "pid": 1234
  }
}
```

### 7. MMVAD Tree Explorer

```json
{
  "tool": "x64dbg_mmvad_tree_explorer",
  "arguments": {
    "action": "explore_vad_tree"
  }
}
```

### 8. LSASS DPAPI Blob Reader

```json
{
  "tool": "x64dbg_lsass_dpapi_blob_reader",
  "arguments": {
    "action": "read_dpapi_blobs"
  }
}
```

### 9. Kernel Pool Feng Shui

```json
{
  "tool": "x64dbg_kernel_pool_feng_shui",
  "arguments": {
    "action": "analyze_pool_layout"
  }
}
```

### 10. Deep Binary Virtualization

```json
{
  "tool": "x64dbg_deep_binary_virtualization",
  "arguments": {
    "action": "vmx_cap_audit_msrs"
  }
}
```

### 11. Specialized Architecture

```json
{
  "tool": "x64dbg_specialized_architecture",
  "arguments": {
    "action": "vmcs_decode_field_encoding",
    "encoding": "0x00004800"
  }
}
```

### 12. Memory Forensics Deep

```json
{
  "tool": "x64dbg_memory_forensics_deep",
  "arguments": {
    "action": "jit_spray_scan",
    "pid": 1234
  }
}
```

### 13. Anti-Analysis Evasion

```json
{
  "tool": "x64dbg_anti_analysis_evasion",
  "arguments": {
    "action": "detect_evasion_techniques"
  }
}
```

### 14. Binary Triage

```json
{
  "tool": "x64dbg_binary_triager",
  "arguments": {
    "action": "triage_binary",
    "binary_path": "C:\\malware\\sample.exe"
  }
}
```

### 15. Code Similarity Engine

```json
{
  "tool": "x64dbg_code_similarity_engine",
  "arguments": {
    "action": "compare_binaries",
    "binary_a": "C:\\bin\\a.exe",
    "binary_b": "C:\\bin\\b.exe"
  }
}
```

### 16. Crypto Hunter

```json
{
  "tool": "x64dbg_crypto_hunter",
  "arguments": {
    "action": "scan_crypto_constants",
    "module": "malware.dll"
  }
}
```

### 17. COM/RPC Walker

```json
{
  "tool": "x64dbg_com_rpc_walker",
  "arguments": {
    "action": "map_com_interfaces",
    "module": "ole32.dll"
  }
}
```

### 18. Go Runtime Helper

```json
{
  "tool": "x64dbg_golang_helper",
  "arguments": {
    "action": "recover_runtime_types",
    "module": "go_binary.exe"
  }
}
```

### 19. .NET Helper

```json
{
  "tool": "x64dbg_dotnet_helper",
  "arguments": {
    "action": "detect_clr_version"
  }
}
```

### 20. Kernel Callback Auditor

```json
{
  "tool": "x64dbg_kernel_callback_auditor",
  "arguments": {
    "action": "enumerate_callbacks"
  }
}
```

---

## Notes

- All tools communicate with the C++ plugin over `127.0.0.1:27042`
- The MCP server validates all parameters with Zod schemas before sending requests
- Debugger state requirements: most inspection tools require the debugger to be paused
- See [docs/REFERENCE.md](docs/REFERENCE.md) for core tool documentation
- See [server/README.md](server/README.md) for installation and configuration
