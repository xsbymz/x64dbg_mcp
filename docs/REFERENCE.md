# x64dbg MCP — Full Reference

Complete reference for the x64dbg MCP server: every tool and action, the architecture,
the build system, configuration, and troubleshooting. The [README](../README.md) is the
quick tour; this is the exhaustive version (kept for humans doing deep work and for AI
agents operating the plugin).

- [How it works](#how-it-works)
- [Tool reference (300 mega-tools)](#tool-reference-300-mega-tools)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Building from source](#building-from-source)
- [Troubleshooting](#troubleshooting)
- [Security](#security)

## How it works

```
                            stdio                        HTTP (localhost)
  MCP Client  <───────────────────>  TypeScript MCP  <──────────────────>  C++ Plugin
  (Claude,                           Server            127.0.0.1:27042     (inside x64dbg)
   Cursor,                           309 mega-tools                       1057+ REST endpoints
   etc.)                             Zod validation                       ~250+ handler files
```

- **C++ Plugin** (`x64dbg_mcp.dp64` / `.dp32`) runs inside x64dbg as a lightweight REST API
  server on `127.0.0.1:27042`. It wraps the x64dbg Bridge/Plugin SDK with 1057+ JSON endpoints
  across 292 handler files.
- **TypeScript MCP Server** (`x64dbg-mcp-server` on npm) implements the MCP protocol over
  stdio. The 300 mega-tools use Zod discriminated unions to validate parameters, then route
  requests to the correct REST endpoint on the plugin via localhost HTTP.

The MCP server waits for the plugin to become available, performs periodic health checks, and
automatically reconnects if x64dbg restarts. By default it waits indefinitely per request
(debugger operations such as run/trace are unbounded); set `X64DBG_MCP_TIMEOUT` for a hard
ceiling. Transient connection failures retry up to 3 times with exponential backoff (timeouts
are not retried).

**Why stdio?** No SSE reconnection issues, no port conflicts, no dropped connections. The MCP
client spawns the server as a child process — it just works.

## Tool reference (300 mega-tools)

Each tool accepts an `action` parameter that selects the specific operation. Parameters are
validated with Zod schemas at runtime.

### Debugger control

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_debug` | `run`, `pause`, `force_pause`, `step_into`, `step_over`, `step_out`, `stop_debug`, `restart_debug`, `run_to_address`, `state`, `wait_event` | Control execution flow, query debugger state, and long-poll for debug events (breakpoint hits, exceptions, step completion) |
| `x64dbg_command` | `execute`, `script`, `evaluate`, `evaluate_all`, `format`, `set_init_script`, `get_init_script`, `get_hash`, `get_events`, `get_log` | Execute raw x64dbg commands, batch scripts, multi-expression evaluation, and query event logs |

### CPU & memory

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_registers` | `get_all`, `get_specific`, `get_flags`, `get_avx512`, `set` | Read/write CPU registers including GPR, flags, and AVX-512 |
| `x64dbg_memory` | `read`, `write`, `info`, `is_valid`, `is_code`, `rwx_audit`, `struct_view`, `allocate`, `free`, `protect`, `map`, `update_map`, `read_batch`, `follow_pointers`, `injected_check`, `compare_sections` | Full memory operations: read (with hex dump), write, W^X / RWX page auditor, dynamic struct schema formatter, batch multi-region reads, pointer chain traversal, allocate, protect, memory map, injected code detection, section comparison against disk |
| `x64dbg_snapshot` | `create`, `diff`, `list` | Cheat Engine-style memory snapshotting and differential scanner (filter changed, unchanged, increased, decreased values) |
| `x64dbg_stack` | `arguments`, `get_call_stack`, `read`, `pointers`, `seh_chain`, `return_address`, `comment` | Smart function argument resolver (x64 fastcall / x86 cdecl with string/pointer dereferencing), call stack unwinding, raw stack reads, SEH chain, return address |

### Code analysis & reverse engineering

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_disassembly` | `at_address`, `function`, `range`, `info`, `assemble` | Disassemble instructions, whole functions, byte ranges (start..end), or assemble new code |
| `x64dbg_analysis` | `function`, `xrefs_to`, `xrefs_from`, `basic_blocks`, `source`, `mnemonic_brief`, `entropy`, `rop_gadgets`, `rop_gadgets_advanced`, `rop_chain_builder`, `vtable`, `vtable_rtti`, `dataflow` | Cross-references, function boundaries, CFG basic blocks, source mapping, Shannon entropy, ROP/JOP gadgets, enhanced gadget scanner with quality scoring, ROP chain builder, C++ VTable reconstructor, VTable+RTTI reconstruction, backward register data-flow dependency slicer |
| `x64dbg_crypto` | `scan` | FindCrypt automated crypto scanner: AES S-Boxes/Rcon, MD5, SHA-1/256/512, ChaCha20/Salsa20, CRC32, Base64, TEA |
| `x64dbg_pe` | `mitigations`, `tls_callbacks`, `deep_info`, `entry_point` | Deep PE inspection: Checksec binary hardening audit (ASLR, DEP/NX, SafeSEH, CFG, /GS cookies), TLS callbacks, 15 PE data directories, entry point RVA |
| `x64dbg_control_flow` | `cfg`, `branch_dest`, `is_jump_taken`, `loops`, `func_type`, `add_function`, `delete_function` | Control flow graph, branch analysis, loop detection, function management |
| `x64dbg_database` | `constants`, `error_codes`, `structs`, `strings` | Query x64dbg's analysis database with limit/offset pagination for module strings |
| `x64dbg_address_convert` | `va_to_file`, `file_to_va` | Convert between virtual addresses and file offsets |
| `x64dbg_watchdog` | *(id parameter)* | Check if a watch expression watchdog has been triggered |

### Breakpoints & tracing

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_breakpoints` | `set_software`, `set_hardware`, `set_memory`, `delete`, `enable`, `disable`, `toggle`, `set_condition`, `set_log`, `reset_hit_count`, `get`, `list`, `configure`, `configure_batch` | Full breakpoint management: software, hardware, memory, conditional, logging, batch |
| `x64dbg_tracing` | `into`, `over`, `run`, `stop`, `status`, `animate`, `conditional_run`, `log_setup`, `hitcount`, `type`, `set_type` | Execution tracing, trace logging, hit counters, conditional tracing, live trace status |
| `x64dbg_telemetry` | `enable`, `disable` | One-click automated logging hooks on Windows API sets (file_io, registry, injection, network, anti_debug) |
| `x64dbg_exceptions` | `set`, `delete`, `list`, `list_codes`, `skip`, `seh_chain` | Exception breakpoints, known exception codes, skip/pass exceptions, and SEH handler chain |

### Symbols & annotations

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_symbols` | `resolve`, `address`, `search`, `list_module`, `get_label`, `set_label`, `get_comment`, `set_comment`, `bookmark` | Symbol resolution, labels, comments, bookmarks |
| `x64dbg_search` | `pattern`, `string`, `xor_scan`, `string_at`, `symbol_auto_complete`, `encode_type` | AOB/byte pattern scan, paginated full-memory string search, 256-key XOR brute-force scanner, symbol autocomplete |
| `x64dbg_modules` | `list`, `get_info`, `get_base`, `get_section`, `get_party` | Loaded modules, base addresses, sections, user/system classification |

### Process & system

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_process` | `basic`, `detailed`, `cmdline`, `elevated`, `dbversion`, `set_cmdline` | Process info, PID, PEB, elevation status, debugger version |
| `x64dbg_threads` | `list`, `current`, `count`, `contexts_all`, `info`, `teb`, `name`, `switch`, `suspend`, `resume`, `context`, `context_set` | Thread enumeration, TEB access, full multi-thread context snapshot, thread context read/write (GPRs, flags, debug registers), thread control |
| `x64dbg_handles` | `list_handles`, `list_tcp`, `list_windows`, `list_heaps`, `get_name`, `close` | Handles, TCP connections, windows, heaps |
| `x64dbg_gui` | `windows` | Inspect GUI windows, dialogs, buttons, controls, and window procedures (WndProc) |
| `x64dbg_antidebug` | `audit`, `hooks`, `peb`, `teb`, `dep`, `hide_debugger` | Comprehensive anti-debug visibility audit, user-mode API/syscall hook detection (EDR/AV), PEB/TEB inspection, DEP status, hide debugger |
| `x64dbg_peb` | `full`, `ldr`, `cmdline`, `env`, `teb_full` | Full PEB/TEB walker: BeingDebugged, NtGlobalFlag, ProcessHeap, LDR lists, ProcessParameters, ActivationContextData, Token, environment block extraction |
| `x64dbg_syscalls` | `ntdll`, `ssn`, `hooks`, `kernel32` | NTDLL/Kernel32 syscall enumeration, SSN extraction, inline hook detection against clean `4C 8B D1 B8` patterns |
| `x64dbg_veh` | *(no parameters)* | Vectored Exception Handling chain enumeration: walks PEB VectoredHandlerList to find registered vectored exception/continue handlers |
| `x64dbg_resources` | `list`, `extract` | PE resource directory enumeration and extraction: list resources by type/name/id, extract resource data as base64 |
| `x64dbg_iathash` | `iat`, `eat` | Import/Export Address Table hash calculation (CRC32 + FNV-1a) for malware family identification and binary diffing |
| `x64dbg_etw_amsi` | *(no parameters)* | Detect ETW/AMSI bypass techniques: patched AmsiScanBuffer, NtTraceEvent, disabled ETW callbacks, hooked Etwp* functions |

### Patching & dumping

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_patches` | `list`, `apply`, `restore`, `export` | Apply byte patches, restore originals, export patches (as C/C++ array, Python/Frida, x64dbg script, or commit directly to a binary file) |
| `x64dbg_dumping` | `pe_header`, `sections`, `imports`, `exports`, `entry_point`, `relocations`, `dump_module`, `fix_iat`, `export_patch_file` | PE analysis, module dumping, IAT reconstruction, patch file export |
| `x64dbg_diffing` | `memory_vs_disk`, `pe_sections`, `patches` | Binary diffing: compare loaded module against on-disk PE to detect hollowing/packing, compare sections between modules, list active byte patches |

### Exploit development

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_crash` | `triage`, `buckets`, `last` | Crash root-cause analysis: exception code classification, faulting instruction disassembly, register snapshot, stack dump, SEH chain, memory page info, heuristic crash bucketing |
| `x64dbg_heap` | `list`, `walk`, `corruption` | Windows heap forensics: enumerate process heaps, walk segments and chunks, detect metadata corruption (double-free, invalid pointers, signature mismatch) |
| `x64dbg_primitives` | `detect`, `trace` | Exploit primitive detection: scan for dangerous functions (memcpy, strcpy, ReadProcessMemory, etc.), set up conditional traces to capture register values at call entry |
| `x64dbg_taint` | `mark`, `clear`, `status`, `trace_step` | Basic taint tracking: mark memory ranges, clear taint, check status, perform one propagation step after stepping the debugger |
| `x64dbg_shellcode` | `execute`, `disassemble` | Shellcode harness: allocate memory, write bytes, execute with optional single-stepping trace capture, linear disassembly of raw bytes |

### Malware analysis

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_config` | `extract`, `strings` | Generic config extractor: scan for base64 blobs, XORed strings with known prefixes, JSON length-prefixed objects, PE headers at unusual addresses; paginated module string scan |
| `x64dbg_yara` | `from_memory`, `from_behavior` | YARA/Sigma rule generation from memory regions (strings + high-entropy patterns) or observed API behavior |
| `x64dbg_unpacker` | `auto`, `entry_candidates` | Automated unpacker and OEP finder: iterative tail-jump tracing, entropy validation, module dumping, and OEP candidate scanning |
| `x64dbg_batch` | *(batch request array)* | Execute multiple independent requests in one HTTP round-trip to reduce latency. Max 20 requests per batch. |

### Memory corruption detection

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_corruption` | `stack_canary`, `format_string`, `heap_overflow`, `uaf_candidates` | Memory corruption vulnerability detection: stack canary/cookie analysis, format string vulnerability scanning, heap metadata overflow detection, use-after-free candidate identification |

### Exploit primitives

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_primitives_advanced` | `arbitrary_read`, `arbitrary_write`, `info_leak`, `stack_pivot` | Advanced exploit primitive enumeration: find functions enabling arbitrary read/write (memcpy, ReadProcessMemory, WriteProcessMemory), information leak sources (NtQueryInformationProcess, EnumWindows), and stack pivot gadgets with quality scoring |

### Obfuscation & control flow analysis

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_obfuscation` | `detect`, `vm_detect`, `string_decrypt`, `opaque_predicates`, `flattening`, `loops`, `branch_analysis`, `indirect_calls` | Obfuscation technique detection: CFG flattening (switch-based state machines), opaque predicates, VM/interpreter detection (dispatch tables, bytecode handlers), string decryption (XOR, rolling XOR, Caesar), loop detection, branch analysis, indirect call/jump enumeration for JOP/ROP |

### Anti-debug & VM detection

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_antidebug_advanced` | `timing_checks`, `hardware_bp_detection`, `ntquery_hooks`, `exception_handlers` | Advanced anti-debug detection: timing-based checks (RDTSC, QPC, GetTickCount), hardware debug register manipulation, NtQueryInformationProcess hooking, exception-based anti-debug (INT3 scanning, SEH tampering) |
| `x64dbg_vm` | `detect`, `registry_artifacts`, `driver_check`, `cpuid_check` | Virtual machine/sandbox detection: comprehensive VM artifact scanning (registry keys, device drivers, CPUID hypervisor signatures, timing anomalies) |

### Fuzzing

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_fuzz` | `harness`, `iterate`, `crash_triage`, `coverage`, `stop` | Fuzzing harness and crash triage: create fuzzing targets, run iterations with input monitoring, automated crash analysis with exploitability scoring, coverage tracking |

### Symbolic execution

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_symbolic` | `constraints`, `solve`, `taint_propagation`, `path_exploration` | Symbolic execution helpers: extract path constraints from disassembly, solve constraints with SMT solver backend, track taint propagation through execution paths, explore alternative feasible paths |

### Enhanced binary diffing

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_diffing_enhanced` | `semantic`, `patch_analysis` | Enhanced binary diffing: semantic comparison between modules, comprehensive patch analysis with exploitability assessment (NOP detection, JMP identification) |

### Kernel exploitation

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_kernel` | `token_steal_check`, `pool_overflow_detection`, `callbacks` | Kernel-mode exploitation helpers: token steal primitive checks, pool overflow detection, kernel callback enumeration (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, CmRegisterCallback) |

### Advanced exploit development

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_rop_builder` | `find_gadgets`, `build_chain`, `validate_chain`, `export_chain` | Advanced ROP chain construction: find gadgets by effect, build/validate chains in memory, export as C/Python/asm. `find_gadgets` accepts `effect` (e.g. `"rax=rbx"`, `"call rax"`), optional `module`, `max_results`. `build_chain` accepts ordered `gadgets[]` with `address`/`purpose`/`args`, optional `target`. `validate_chain` accepts `chain_address` and `chain_length`. `export_chain` accepts `gadgets[]`, `format` (`asm`/`c`/`python`/`c_shellcode`), `include_args`. |
| `x64dbg_gadget_semantic_builder` | *(see ADVANCED_TOOLS.md)* | Constraint-based semantic gadget synthesis. |
| `x64dbg_heap_gadget_finder` | *(see ADVANCED_TOOLS.md)* | Segment heap & NT heap exploitation primitives. |
| `x64dbg_symbolic_exploit_finder` | *(see ADVANCED_TOOLS.md)* | SMT constraint-guided crash path exploration. |
| `x64dbg_exploit_likelihood_scorer` | *(see ADVANCED_TOOLS.md)* | Composite exploitability probability scoring. |
| `x64dbg_vuln_chain_discoverer` | *(see ADVANCED_TOOLS.md)* | Multi-stage exploit chain synthesis. |
| `x64dbg_api_dependency_graph` | *(see ADVANCED_TOOLS.md)* | API call dependency mapping. |
| `x64dbg_string_decryption_automation` | *(see ADVANCED_TOOLS.md)* | Automated multi-algorithm string decryption. |
| `x64dbg_jit_rop_analyzer` | *(see ADVANCED_TOOLS.md)* | JIT ROP gadget analysis. |
| `x64dbg_gadget_quality_scorer` | *(see ADVANCED_TOOLS.md)* | Gadget reliability scoring. |
| `x64dbg_semantic_patcher` | *(see ADVANCED_TOOLS.md)* | Intent-based patching. |

### Hardware tracing & CET

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_intel_pt_tracer` | `status`, `decode_trace`, `export_coverage_bitmap` | Intel Processor Trace hardware execution decoder and AFL++ coverage bitmap exporter. `status` checks PT availability; `decode_trace` decodes raw packet stream; `export_coverage_bitmap` exports AFL++-compatible bitmap. |
| `x64dbg_cet_shadow_stack_manipulator` | `read_shadow_stack`, `audit_ssp_tokens`, `scan_endbr_violations` | Intel CET shadow stack, RSTORSSP tokens, and Indirect Branch Tracking (IBT) validator. `read_shadow_stack` dumps shadow stack contents; `audit_ssp_tokens` validates SSP token integrity; `scan_endbr_violations` scans for missing `ENDBRANCH` markers. |
| `x64dbg_speculative_gadget_hunter` | *(see ADVANCED_TOOLS.md)* | Speculative execution gadget discovery. |
| `x64dbg_xsave_avx512_inspector` | *(see ADVANCED_TOOLS.md)* | XSAVE/AVX-512 state inspector. |
| `x64dbg_lbr_branch_ring_inspector` | *(see ADVANCED_TOOLS.md)* | LBR branch ring inspector. |
| `x64dbg_amx_matrix_inspector` | *(see ADVANCED_TOOLS.md)* | AMX matrix inspector. |

### Deep forensics & kernel internals

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_mmvad_tree_explorer` | *(see ADVANCED_TOOLS.md)* | MMVAD tree explorer for VAD-based forensics. |
| `x64dbg_kernel_pool_feng_shui` | *(see ADVANCED_TOOLS.md)* | Kernel pool layout analysis and chunk grooming. |
| `x64dbg_lsass_dpapi_blob_reader` | *(see ADVANCED_TOOLS.md)* | LSASS DPAPI blob reader. |
| `x64dbg_ntfs_mft_artifact_carver` | *(see ADVANCED_TOOLS.md)* | NTFS MFT artifact carver. |
| `x64dbg_kernel_callback_auditor` | *(see ADVANCED_TOOLS.md)* | Kernel callback enumeration and integrity check. |
| `x64dbg_kernel_structures` | *(see ADVANCED_TOOLS.md)* | KTHREAD/KPCR/Object Types/DKOM/Driver Object/Dispatch/HAL/NTFS/KUSER/Prefetch/Token/Pool/LSASS/WFP/NDIS/Prefetch/Token/Pool/LSASS/WFP/NDIS/Prefetch/Token/Pool/LSASS/WFP/NDIS/Prefetch/Token/Pool/LSASS/WFP/NDIS/Prefetch/Token/Pool/LSASS/WFP/NDIS/Prefetch/Token/Pool/LSASS/WFP/NDIS |
| `x64dbg_hal_dispatch_hijack_auditor` | *(see ADVANCED_TOOLS.md)* | HAL dispatch hijack auditor. |
| `x64dbg_wfp_callout_auditor` | *(see ADVANCED_TOOLS.md)* | WFP callout auditor. |
| `x64dbg_ndis_lwf_chain_inspector` | *(see ADVANCED_TOOLS.md)* | NDIS LWF chain inspector. |
| `x64dbg_prefetch_forensics_engine` | *(see ADVANCED_TOOLS.md)* | Prefetch forensics engine. |
| `x64dbg_token_impersonation_chain_walker` | *(see ADVANCED_TOOLS.md)* | Token impersonation chain walker. |

### Specialized architecture & virtualization

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_vbs_hvci_detector` | `get_status`, `inspect_isolated_user_mode`, `check_code_integrity` | Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI), Credential Guard, and Isolated User Mode (IUM) trustlet state inspector. |
| `x64dbg_hypervisor_detector` | `full_audit`, `cpuid_leaves`, `timing_variance`, `synthetic_msrs` | Detect and audit hypervisor environments (Hyper-V, KVM, Xen, VMware, VirtualBox) via synthetic MSRs, CPUID leaves (0x40000000+), SLDT/SIDT/SGDT instruction behaviors, and TSC timing variance. |
| `x64dbg_deep_binary_virtualization` | *(see ADVANCED_TOOLS.md)* | VMX capabilities, EPT page walker, Intel PT decoder, Authenticode leaf parser, Catalog DB lookup, Security Descriptor DACL evaluator, DWARF debug parser, and more. |
| `x64dbg_specialized_architecture` | *(see ADVANCED_TOOLS.md)* | VMCS field decoder, paging walker (4-level/5-level/LA57/PCID), LoadConfig deep parser (CFG/XFG/CastGuard/CET), SMT-LIB2 solver bridge. |

### Malware analysis & unpacking (extended)

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_crypto_hunter` | *(see ADVANCED_TOOLS.md)* | Crypto lookup table scanner. |
| `x64dbg_com_rpc_walker` | *(see ADVANCED_TOOLS.md)* | COM VTable/RPC mapper. |
| `x64dbg_dotnet_helper` | *(see ADVANCED_TOOLS.md)* | CLR version detection and metadata inspection. |
| `x64dbg_golang_helper` | *(see ADVANCED_TOOLS.md)* | Go runtime recovery and goroutine inspection. |
| `x64dbg_rust_helper` | *(see ADVANCED_TOOLS.md)* | Rust symbol demangling. |
| `x64dbg_delphi_helper` | *(see ADVANCED_TOOLS.md)* | Delphi VMT inspector. |
| `x64dbg_hook_scanner` | *(see ADVANCED_TOOLS.md)* | User-mode hook scanner. |
| `x64dbg_driver_auditor` | *(see ADVANCED_TOOLS.md)* | Kernel driver inspector. |
| `x64dbg_ipc_monitor` | *(see ADVANCED_TOOLS.md)* | Named Pipes/Mailslots/Shared Sections monitor. |
| `x64dbg_cert_authenticode` | *(see ADVANCED_TOOLS.md)* | Authenticode verification. |
| `x64dbg_hotpatch_engine` | *(see ADVANCED_TOOLS.md)* | Live function hooking. |
| `x64dbg_unpacker` | `auto`, `entry_candidates` | Automated unpacker and OEP finder: iterative tail-jump tracing, entropy validation, module dumping, and OEP candidate scanning. |

### Anti-debug, anti-analysis & evasion

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_anti_analysis_evasion` | *(see ADVANCED_TOOLS.md)* | Anti-analysis evasion techniques. |
| `x64dbg_anti_anti_debug_engine` | *(see ADVANCED_TOOLS.md)* | Anti-anti-debug engine. |
| `x64dbg_memory_forensics_deep` | *(see ADVANCED_TOOLS.md)* | JIT spray detection, UAF tag/analyze, memory forensics timeline, PEB LDR integrity, code signing memory validator. |

### Binary intelligence & triage

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_binary_triager` | *(see ADVANCED_TOOLS.md)* | One-shot binary security triage. |
| `x64dbg_code_similarity_engine` | *(see ADVANCED_TOOLS.md)* | CFG isomorphism + fuzzy hashing. |
| `x64dbg_struct_reconstructor` | *(see ADVANCED_TOOLS.md)* | C/C++ struct reconstruction. |
| `x64dbg_binary_analysis_deep` | *(see ADVANCED_TOOLS.md)* | Deep binary analysis tools. |
| `x64dbg_legacy_debugger_tools` | *(see ADVANCED_TOOLS.md)* | Legacy debugger tools. |
| `x64dbg_firmware_uefi_tools` | *(see ADVANCED_TOOLS.md)* | UEFI firmware tools. |
| `x64dbg_cpu_internals_tools` | *(see ADVANCED_TOOLS.md)* | CPU internals tools. |

### Injection, persistence & C2

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_injection` | *(see ADVANCED_TOOLS.md)* | Process injection detection and analysis. |
| `x64dbg_injection_persistence` | *(see ADVANCED_TOOLS.md)* | Injection persistence mechanisms. |
| `x64dbg_network_c2_protocol` | *(see ADVANCED_TOOLS.md)* | Network C2 protocol analysis. |
| `x64dbg_cobalt_strike_beacon` | *(see ADVANCED_TOOLS.md)* | Cobalt Strike beacon detection. |
| `x64dbg_named_pipe_c2` | *(see ADVANCED_TOOLS.md)* | Named pipe C2 detection. |
| `x64dbg_doh_detector` | *(see ADVANCED_TOOLS.md)* | DNS-over-HTTPS detector. |
| `x64dbg_raw_socket` | *(see ADVANCED_TOOLS.md)* | Raw socket inspector. |
| `x64dbg_http2_frame` | *(see ADVANCED_TOOLS.md)* | HTTP/2 frame analyzer. |
| `x64dbg_protobuf_decoder` | *(see ADVANCED_TOOLS.md)* | Protocol buffer decoder. |

### Coverage, watch & automation

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_watch` | *(see ADVANCED_TOOLS.md)* | Watch expression automation. |
| `x64dbg_script_engine` | *(see ADVANCED_TOOLS.md)* | Script engine automation. |
| `x64dbg_coverage` | *(see ADVANCED_TOOLS.md)* | Code coverage tools. |
| `x64dbg_memwatch` | *(see ADVANCED_TOOLS.md)* | Memory watch tools. |
| `x64dbg_stringxref` | *(see ADVANCED_TOOLS.md)* | String cross-reference tools. |
| `x64dbg_autoannotate` | *(see ADVANCED_TOOLS.md)* | Auto-annotation tools. |
| `x64dbg_calltree` | *(see ADVANCED_TOOLS.md)* | N-level call tree generator. |
| `x64dbg_branch_coverage` | *(see ADVANCED_TOOLS.md)* | Branch coverage tools. |
| `x64dbg_api_logger` | *(see ADVANCED_TOOLS.md)* | API call logger. |

### Security & Operations

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_audit` | `log`, `stats`, `clear` | View audit log of all MCP requests and security events, get connection/request statistics, clear audit log |
| `x64dbg_session` | `save`, `restore`, `list`, `delete` | Save and restore debugger sessions (breakpoints, patches, labels, comments, bookmarks) to/from disk |
| `x64dbg_security` | `status`, `verify_token`, `hardening_report` | Security posture verification: auth status, rate limiting status, token validation, full hardening report |
| `x64dbg_flow_visualizer` | *(see ADVANCED_TOOLS.md)* | Mermaid/Graphviz flowcharts. |

---

## MCP Dynamic Resources (`x64dbg://...`)

The server exposes live debugger state as read-only, dynamic MCP resources for zero-overhead ambient context:

| Resource URI | Description |
| :--- | :--- |
| `x64dbg://state` | Current execution state (running, paused, stopped, PID, TID) |
| `x64dbg://registers` | Live CPU registers (GPRs, flags, AVX-512) |
| `x64dbg://stack/top` | Top stack slots with dereferenced pointer symbols and modules |
| `x64dbg://stack/arguments` | Current function caller parameters (x64 fastcall registers + stack) with string/pointer previews |
| `x64dbg://disasm/cip` | Disassembly window around current instruction pointer (CIP) |
| `x64dbg://callstack` | Reconstructed call stack frames with return addresses |
| `x64dbg://modules` | List of all loaded PE modules with bases and sizes |
| `x64dbg://breakpoints` | Active software, hardware, and memory breakpoints |
| `x64dbg://patches` | All active byte patches vs original image bytes |
| `x64dbg://seh` | Structured Exception Handling (SEH) record chain |
| `x64dbg://antidebug/audit` | Comprehensive anti-debugging detection & stealth audit report |
| `x64dbg://antidebug/hooks` | User-mode NTDLL/Kernel32 syscall and API hook audit report (EDR/detours) |
| `x64dbg://memory/rwx` | Real-time audit of W^X violations (RWX pages) and unbacked private executable memory allocations |
| `x64dbg://threads/all` | Complete multi-thread snapshot (TID, CIP, TEB, Name, State) |

---

## MCP Prompts (Expert Workflows)

Turnkey reverse-engineering and exploit analysis prompt templates:

1. **`unpack_oep_finder`** — Systematic playbook for unpacking binaries, inspecting TLS callbacks, monitoring section transitions, and dumping at OEP.
2. **`diagnose_crash`** — Complete crash root-cause diagnostic (SEH, registers, faulting instruction, RSP stack, page protections).
3. **`crypto_identifier`** — Automated FindCrypt scanning, cross-reference discovery, and key extraction.
4. **`anti_anti_debug_triage`** — PEB/TEB flag auditing, timing checks, and stealth patching.
5. **`api_behavior_profiler`** — Windows API telemetry monitoring for File I/O, Registry, Injection, Network C2, and Anti-Debug.
6. **`xor_string_deobfuscator`** — Brute-force scan memory for XOR-encoded C2 URLs, API strings, and registry keys across all 256 single-byte keys.
7. **`edr_hook_hunter`** — Audit loaded modules and NTDLL syscalls for inline detours, EDR hooks, and security software trampolines.
8. **`rop_chain_planner`** — Scan executable modules for ROP gadgets and catalog return-oriented sequences (pop registers, stack pivots, memory writes).
9. **`binary_hardening_audit`** — Full Checksec mitigation assessment (ASLR, DEP, SafeSEH, CFG, /GS cookies) and memory W^X permission integrity audit.
10. **`vtable_class_reconstructor`** — Reconstruct C++ virtual function table layout, method prototypes, and class hierarchy from object pointers.
11. **`register_provenance_slicer`** — Backward data-flow slicing on CPU registers to determine their exact origin (memory dereference, arithmetic, immediate, or call return).
12. **`crash_triage_automated`** — Automated crash bucketing and root-cause extraction using the new crash analysis tools.
13. **`heap_forensics`** — Walk process heaps, detect corruption, and identify use-after-free or double-free vulnerabilities.
14. **`syscall_hook_detector`** — Enumerate NTDLL/Kernel32 syscall stubs, extract SSNs, and detect inline hooks planted by EDR/AV.
15. **`config_extraction`** — Scan memory for malware configuration blobs: base64, XORed strings, JSON objects, and PE headers at unusual addresses.
16. **`taint_tracking_workflow`** — Mark attacker-controlled memory as tainted, step the debugger, and track where taint propagates through registers and memory.
17. **`memory_corruption_analysis`** — Detect stack canaries, format string vulnerabilities, heap overflow indicators, and use-after-free candidates in target binary.
18. **`exploit_primitive_enumeration`** — Systematically enumerate arbitrary read/write primitives, information leak sources, and stack pivot gadgets for exploit chain construction.
19. **`obfuscation_analysis`** — Detect control flow flattening, opaque predicates, VM-based obfuscation, and attempt string decryption. Identify dead code and instruction substitution patterns.
20. **`anti_debug_vm_detection`** — Comprehensive anti-debug and VM detection: timing checks, hardware debug register inspection, NtQuery hooks, exception handlers, registry artifacts, driver checks, and CPUID hypervisor detection.
21. **`fuzzing_workflow`** — Set up fuzzing harness, run iterations, monitor for crashes, perform automated crash triage with exploitability scoring, and track code coverage.
22. **`symbolic_execution_workflow`** — Extract path constraints from current execution, solve constraints using SMT solver backend, track taint propagation, and explore alternative execution paths.
23. **`binary_diffing_advanced`** — Semantic diff between binary versions, patch analysis with exploitability assessment, identify NOPs, JMPs, and code modifications.
24. **`kernel_exploitation_primitives`** — Kernel-mode exploitation helpers: token steal primitive checks, pool overflow detection, and kernel callback enumeration for privilege escalation.

## Configuration

Environment variables for the MCP server:

| Variable | Default | Description |
|----------|---------|-------------|
| `X64DBG_MCP_HOST` | `127.0.0.1` | Plugin REST API host |
| `X64DBG_MCP_PORT` | `27042` | Plugin REST API port |
| `X64DBG_MCP_TIMEOUT` | `0` | Per-request timeout in milliseconds. `0` = wait indefinitely (default), since debugger operations like run/trace are unbounded. Set a positive value for a hard ceiling. |
| `X64DBG_MCP_RETRIES` | `3` | Retry count on transient connection failures (not applied to timeouts, 4xx/5xx, or malformed responses) |
| `X64DBG_MCP_TOKEN` | *(empty)* | Bearer token sent on every request. Must match the plugin's **Settings > Token**. Empty = no auth. |

Set these in your MCP client config if needed:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "npx",
      "args": ["-y", "x64dbg-mcp-server"],
      "env": {
        "X64DBG_MCP_PORT": "27043"
      }
    }
  }
}
```

### Plugin commands

Control the REST API from the x64dbg command bar:

```
mcpserver start     Start the HTTP server
mcpserver stop      Stop the HTTP server
mcpserver status    Show server status and port
```

The plugin also provides GUI dialogs accessible from `Plugins > x64dbg MCP server`:

- **Settings...** — configure host, port, auto-start, and the optional auth token (persisted via BridgeSetting)
- **About...** — version, live server status (green/red), GitHub link, Discord contact

## Architecture

### System overview

```
┌─────────────────────────────────────────────────────────────────┐
│  MCP Client (Claude Code, Cursor, etc.)                         │
│  Spawns server as child process, communicates via stdin/stdout   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ stdio (MCP JSON-RPC)
┌──────────────────────────▼──────────────────────────────────────┐
│  TypeScript MCP Server (x64dbg-mcp-server)                      │
│                                                                 │
│  309 tools registered via @modelcontextprotocol/sdk              │
│  Zod discriminated unions validate action + parameters          │
│  HttpClient: auto-reconnect, health checks, retry logic         │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP GET/POST (127.0.0.1:27042)
┌──────────────────────────▼──────────────────────────────────────┐
│  C++ Plugin DLL (x64dbg_mcp.dp64 / .dp32)                      │
│                                                                 │
│  Winsock2 HTTP server, JSON via nlohmann/json                   │
│  ~250+ handler files, 1057+ REST endpoints                      │
│  c_bridge_executor: thread-safe calls to x64dbg SDK             │
└──────────────────────────┬──────────────────────────────────────┘
                           │ x64dbg Bridge/Plugin SDK
┌──────────────────────────▼──────────────────────────────────────┐
│  x64dbg Debugger Engine                                         │
│  DbgFunctions(), Script API, Bridge API                         │
└─────────────────────────────────────────────────────────────────┘
```

### Project structure

```
x64dbg_mcp/
├── build.ps1                       # One-shot build (SDK fetch + plugin + optional server)
├── install.ps1                     # Auto-detecting plugin installer (registry/process/PATH)
├── plugin/                         # C++ x64dbg plugin (REST API server)
│   ├── CMakeLists.txt              # Build config (C++23, clang-cl)
│   ├── CMakePresets.json           # x64-release, x32-release, x64-debug presets
│   ├── fetch-sdk.ps1               # Version-aware x64dbg pluginsdk fetch (headers + libs)
│   ├── plugin.def                  # DLL export definitions
│   ├── sdk/                        # x64dbg Plugin SDK headers (libs fetched, gitignored)
│   │   ├── _plugins.h              # Plugin API
│   │   ├── _dbgfunctions.h         # DbgFunctions() interface
│   │   ├── bridgemain.h            # Bridge API
│   │   ├── jansson/                # JSON library (SDK dependency)
│   │   └── *.lib                   # x64bridge, x32bridge, x64dbg, x32dbg (fetched)
│   └── src/
│       ├── plugin_main.cpp/.h      # Plugin entry, /api/health, /api/process/info
│       ├── bridge/
│       │   └── c_bridge_executor.* # Thread-safe wrapper for x64dbg API calls
│       ├── handlers/               # ~250+ REST endpoint handler files
│       │   ├── debug_handler.cpp            # /api/debug/* (11 endpoints)
│       │   ├── register_handler.cpp         # /api/registers/* (5 endpoints)
│       │   ├── memory_handler.cpp           # /api/memory/* (14 endpoints)
│       │   ├── breakpoint_handler.cpp       # /api/breakpoints/* (15 endpoints)
│       │   ├── disasm_handler.cpp           # /api/disasm/* (4 endpoints)
│       │   ├── module_handler.cpp           # /api/modules/* (5 endpoints)
│       │   ├── thread_handler.cpp           # /api/threads/* (12 endpoints)
│       │   ├── stack_handler.cpp            # /api/stack/* (7 endpoints)
│       │   ├── symbol_handler.cpp           # /api/symbols/* (4 endpoints)
│       │   ├── annotation_handler.cpp       # /api/labels/*, /api/comments/*, /api/bookmarks/* (5 endpoints)
│       │   ├── search_handler.cpp           # /api/search/* (5 endpoints)
│       │   ├── command_handler.cpp          # /api/command/* (10 endpoints)
│       │   ├── analysis_handler.cpp         # /api/analysis/* (16 endpoints)
│       │   ├── tracing_handler.cpp          # /api/trace/* (10 endpoints)
│       │   ├── dumping_handler.cpp          # /api/dump/*, /api/patches/export_file (10 endpoints)
│       │   ├── patch_handler.cpp            # /api/patches/* (4 endpoints)
│       │   ├── memmap_handler.cpp           # /api/memmap/* (2 endpoints)
│       │   ├── antidebug_handler.cpp        # /api/antidebug/* (6 endpoints)
│       │   ├── antidebug_advanced_handler.cpp # /api/antidebug/* advanced (4 endpoints)
│       │   ├── vm_detection_handler.cpp     # /api/vm/* (4 endpoints)
│       │   ├── exceptions_handler.cpp       # /api/exceptions/* (5 endpoints)
│       │   ├── process_handler.cpp          # /api/process/* (5 endpoints)
│       │   ├── handles_handler.cpp          # /api/handles/* (6 endpoints)
│       │   ├── controlflow_handler.cpp      # /api/cfg/* (7 endpoints)
│       │   ├── control_flow_handler.cpp     # /api/cfg/* advanced (4 endpoints)
│       │   ├── crash_handler.cpp            # /api/crash/* (3 endpoints)
│       │   ├── peb_handler.cpp              # /api/peb/*, /api/teb/* (5 endpoints)
│       │   ├── syscall_handler.cpp          # /api/syscalls/* (4 endpoints)
│       │   ├── taint_handler.cpp            # /api/taint/* (4 endpoints)
│       │   ├── batch_handler.cpp            # /api/batch/* (1 endpoint)
│       │   ├── yara_handler.cpp             # /api/yara/* (2 endpoints)
│       │   ├── heap_handler.cpp             # /api/heap/* (3 endpoints)
│       │   ├── resource_handler.cpp         # /api/resources/* (2 endpoints)
│       │   ├── veh_handler.cpp              # /api/veh/* (1 endpoint)
│       │   ├── iathash_handler.cpp          # /api/iathash/*, /api/eathash/* (2 endpoints)
│       │   ├── etw_amsi_handler.cpp         # /api/etw_amsi/* (1 endpoint)
│       │   ├── primitive_handler.cpp        # /api/primitive/* (2 endpoints)
│       │   ├── exploit_primitives_handler.cpp # /api/primitives/* (4 endpoints)
│       │   ├── config_handler.cpp           # /api/config/* (2 endpoints)
│       │   ├── unpacker_handler.cpp         # /api/unpacker/* (2 endpoints)
│       │   ├── security_handler.cpp         # /api/security/* (3 endpoints)
│       │   ├── audit_handler.cpp            # /api/audit/* (3 endpoints)
│       │   ├── session_handler.cpp          # /api/session/* (3 endpoints)
│       │   ├── corruption_handler.cpp       # /api/corruption/* (4 endpoints)
│       │   ├── obfuscation_handler.cpp      # /api/obfuscation/* (4 endpoints)
│       │   ├── fuzzing_handler.cpp          # /api/fuzz/* (5 endpoints)
│       │   ├── symbolic_handler.cpp         # /api/symbolic/* (4 endpoints)
│       │   ├── diffing_enhanced_handler.cpp # /api/diff/* enhanced (2 endpoints)
│       │   └── kernel_handler.cpp           # /api/kernel/* (3 endpoints)
│       ├── http/
│       │   ├── c_http_server.*     # Winsock2 HTTP server (localhost only)
│       │   ├── c_http_router.*     # Method + path routing
│       │   ├── auth.h              # Authentication & RBAC
│       │   ├── rate_limiter.h      # Rate limiting
│       │   ├── audit_logger.h      # Audit logging
│       │   ├── s_http_request.h    # Request struct (method, path, body, query, client_ip)
│       │   └── s_http_response.h   # Response helpers (ok, bad_request, conflict, etc.)
│       ├── ui/
│       │   ├── settings_dialog.*   # Settings dialog (host, port, auto-start, token)
│       │   └── about_dialog.*      # About dialog (version, status, links)
│       └── util/
│           ├── format_utils.*      # Address formatting, hex parsing
│           ├── input_sanitizer.h   # Expression/command validation
│           └── path_sanitizer.h    # Path traversal prevention
│
├── server/                         # TypeScript MCP server (npm package)
│   ├── package.json                # x64dbg-mcp-server
│   ├── tsconfig.json               # ES2022, Node16, strict mode
│   ├── server.json                 # MCP registry manifest
│   └── src/
│       ├── index.ts                # McpServer entry, stdio transport, graceful shutdown
│       ├── config.ts               # Environment variable config
│       ├── http_client.ts          # HTTP client with auto-reconnect and health monitoring
│       └── tools/                  # ~280+ tool files, 309 MCP tools
│           ├── index.ts            # Registers all tools on the McpServer
│           ├── debug.ts            # x64dbg_debug
│           ├── registers.ts        # x64dbg_registers
│           ├── memory.ts           # x64dbg_memory (includes memmap)
│           ├── disassembly.ts      # x64dbg_disassembly
│           ├── breakpoints.ts      # x64dbg_breakpoints
│           ├── symbols.ts          # x64dbg_symbols (includes labels, comments, bookmarks)
│           ├── stack.ts            # x64dbg_stack
│           ├── threads.ts          # x64dbg_threads
│           ├── modules.ts          # x64dbg_modules
│           ├── search.ts           # x64dbg_search
│           ├── command.ts          # x64dbg_command
│           ├── analysis.ts         # x64dbg_analysis
│           ├── tracing.ts          # x64dbg_tracing
│           ├── dumping.ts          # x64dbg_dumping
│           ├── antidebug.ts        # x64dbg_antidebug
│           ├── antidebug_advanced.ts # x64dbg_antidebug_advanced
│           ├── exceptions.ts       # x64dbg_exceptions
│           ├── process.ts          # x64dbg_process
│           ├── handles.ts          # x64dbg_handles
│           ├── controlflow.ts      # x64dbg_control_flow
│           ├── patches.ts          # x64dbg_patches
│           ├── crypto.ts           # x64dbg_crypto
│           ├── pe.ts               # x64dbg_pe
│           ├── snapshot.ts         # x64dbg_snapshot
│           ├── telemetry.ts        # x64dbg_telemetry
│           ├── gui.ts              # x64dbg_gui
│           ├── crash.ts            # x64dbg_crash
│           ├── peb.ts              # x64dbg_peb
│           ├── syscalls.ts         # x64dbg_syscalls
│           ├── heap.ts             # x64dbg_heap
│           ├── primitives.ts       # x64dbg_primitives
│           ├── config.ts           # x64dbg_config
│           ├── taint.ts            # x64dbg_taint
│           ├── batch.ts            # x64dbg_batch
│           ├── yara.ts             # x64dbg_yara
│           ├── shellcode.ts        # x64dbg_shellcode
│           ├── diffing.ts          # x64dbg_diffing
│           ├── diffing_enhanced.ts # x64dbg_diffing_enhanced
│           ├── resources.ts        # x64dbg_resources
│           ├── veh.ts              # x64dbg_veh
│           ├── iathash.ts          # x64dbg_iathash
│           ├── etw_amsi.ts         # x64dbg_etw_amsi
│           ├── unpacker.ts         # x64dbg_unpacker
│           ├── audit.ts            # x64dbg_audit
│           ├── session.ts          # x64dbg_session
│           ├── security.ts         # x64dbg_security
│           ├── corruption.ts       # x64dbg_corruption
│           ├── exploit_primitives.ts # x64dbg_primitives_advanced
│           ├── obfuscation.ts      # x64dbg_obfuscation
│           ├── antidebug_advanced.ts # x64dbg_antidebug_advanced
│           ├── fuzzing.ts          # x64dbg_fuzz
│           ├── symbolic.ts         # x64dbg_symbolic
│           ├── kernel.ts           # x64dbg_kernel
│           ├── rop_builder.ts      # x64dbg_rop_builder
│           ├── intel_pt_tracer.ts  # x64dbg_intel_pt_tracer
│           ├── cet_shadow_stack_manipulator.ts # x64dbg_cet_shadow_stack_manipulator
│           ├── vbs_hvci_detector.ts # x64dbg_vbs_hvci_detector
│           ├── hypervisor_detector.ts # x64dbg_hypervisor_detector
│           ├── vulnhunt.ts         # x64dbg_vulnhunt_*
│           ├── calltree.ts         # x64dbg_calltree
│           ├── coverage.ts         # x64dbg_coverage
│           ├── branch_coverage.ts  # x64dbg_branch_coverage
│           ├── api_logger.ts       # x64dbg_api_logger
│           ├── injection.ts        # x64dbg_injection
│           ├── memory_classifier.ts # x64dbg_memory_classifier
│           ├── stack_inspector.ts  # x64dbg_stack_inspector
│           ├── import_forge.ts     # x64dbg_import_forge
│           ├── instruction_emulator.ts # x64dbg_instruction_emulator
│           ├── hollowing_detector.ts # x64dbg_hollowing_detector
│           ├── watch.ts            # x64dbg_watch
│           ├── script_engine.ts    # x64dbg_script_engine
│           ├── memwatch.ts         # x64dbg_memwatch
│           ├── stringxref.ts       # x64dbg_stringxref
│           ├── autoannotate.ts     # x64dbg_autoannotate
│           ├── behavior_chain_extractor.ts # x64dbg_behavior_chain_extractor
│           ├── c2_pattern_analyzer.ts # x64dbg_c2_pattern_analyzer
│           ├── dead_code_analyzer.ts # x64dbg_dead_code_analyzer
│           ├── signature_generator.ts # x64dbg_signature_generator
│           ├── encoding_detector.ts # x64dbg_encoding_detector
│           ├── compression_detector.ts # x64dbg_compression_detector
│           ├── exploit_likelihood_scorer.ts # x64dbg_exploit_likelihood_scorer
│           ├── vuln_chain_discoverer.ts # x64dbg_vuln_chain_discoverer
│           ├── code_similarity_engine.ts # x64dbg_code_similarity_engine
│           ├── struct_reconstructor.ts # x64dbg_struct_reconstructor
│           ├── crypto_hunter.ts    # x64dbg_crypto_hunter
│           ├── com_rpc_walker.ts   # x64dbg_com_rpc_walker
│           ├── hw_state_inspector.ts # x64dbg_hw_state_inspector
│           ├── binary_triager.ts   # x64dbg_binary_triager
│           ├── golang_helper.ts    # x64dbg_golang_helper
│           ├── dotnet_helper.ts    # x64dbg_dotnet_helper
│           ├── rust_helper.ts      # x64dbg_rust_helper
│           ├── ipc_monitor.ts      # x64dbg_ipc_monitor
│           ├── cert_authenticode.ts # x64dbg_cert_authenticode
│           ├── hotpatch_engine.ts  # x64dbg_hotpatch_engine
│           ├── hook_scanner.ts     # x64dbg_hook_scanner
│           ├── driver_auditor.ts   # x64dbg_driver_auditor
│           ├── exception_tracer.ts # x64dbg_exception_tracer
│           ├── flow_visualizer.ts  # x64dbg_flow_visualizer
│           ├── pe_overlay_analyzer.ts # x64dbg_pe_overlay_analyzer
│           ├── delphi_helper.ts    # x64dbg_delphi_helper
│           ├── token_privilege_auditor.ts # x64dbg_token_privilege_auditor
│           ├── relocation_fixer.ts # x64dbg_relocation_fixer
│           ├── call_convention_inferrer.ts # x64dbg_call_convention_inferrer
│           ├── symbolic_evaluator.ts # x64dbg_symbolic_evaluator
│           ├── network_socket_tracker.ts # x64dbg_network_socket_tracker
│           ├── entropy_heatmap.ts  # x64dbg_entropy_heatmap
│           ├── rich_header_analyzer.ts # x64dbg_rich_header_analyzer
│           ├── file_activity_tracer.ts # x64dbg_file_activity_tracer
│           ├── registry_activity_tracer.ts # x64dbg_registry_activity_tracer
│           ├── thread_stack_differ.ts # x64dbg_thread_stack_differ
│           ├── vtable_dumper.ts    # x64dbg_vtable_dumper
│           ├── module_rebaser.ts   # x64dbg_module_rebaser
│           ├── service_inspector.ts # x64dbg_service_inspector
│           ├── minidump_generator.ts # x64dbg_minidump_generator
│           ├── tls_callback_analyzer.ts # x64dbg_tls_callback_analyzer
│           ├── pdb_symbol_downloader.ts # x64dbg_pdb_symbol_downloader
│           ├── seh_unwind_table_parser.ts # x64dbg_seh_unwind_table_parser
│           ├── resource_payload_carver.ts # x64dbg_resource_payload_carver
│           ├── com_type_library_parser.ts # x64dbg_com_type_library_parser
│           ├── dotnet_metadata_tables.ts # x64dbg_dotnet_metadata_tables
│           ├── peb_teb_advanced.ts # x64dbg_peb_teb_advanced
│           ├── fls_fiber_inspector.ts # x64dbg_fls_fiber_inspector
│           ├── apc_queue_inspector.ts # x64dbg_apc_queue_inspector
│           ├── job_object_inspector.ts # x64dbg_job_object_inspector
│           ├── pipe_data_interceptor.ts # x64dbg_pipe_data_interceptor
│           ├── rpc_alpc_inspector.ts # x64dbg_rpc_alpc_inspector
│           ├── string_table_extractor.ts # x64dbg_string_table_extractor
│           ├── exception_filter_tester.ts # x64dbg_exception_filter_tester
│           ├── memory_permission_watcher.ts # x64dbg_memory_permission_watcher
│           ├── heap_leak_detector.ts # x64dbg_heap_leak_detector
│           ├── deadlock_detector.ts # x64dbg_deadlock_detector
│           ├── handle_duplicator.ts # x64dbg_handle_duplicator
│           ├── dll_hijack_auditor.ts # x64dbg_dll_hijack_auditor
│           ├── entropy_delta_monitor.ts # x64dbg_entropy_delta_monitor
│           ├── x86_x64_assembler.ts # x64dbg_x86_x64_assembler
│           ├── instruction_decoder.ts # x64dbg_instruction_decoder
│           ├── pe_security_directory.ts # x64dbg_pe_security_directory
│           ├── debug_directory_parser.ts # x64dbg_debug_directory_parser
│           ├── load_config_directory.ts # x64dbg_load_config_directory
│           ├── cfg_guard_table_checker.ts # x64dbg_cfg_guard_table_checker
│           ├── memory_pattern_replacer.ts # x64dbg_memory_pattern_replacer
│           ├── string_obfuscation_detector.ts # x64dbg_string_obfuscation_detector
│           ├── api_call_synthesizer.ts # x64dbg_api_call_synthesizer
│           ├── branch_target_tracer.ts # x64dbg_branch_target_tracer
│           ├── window_message_logger.ts # x64dbg_window_message_logger
│           ├── event_tracing_for_windows.ts # x64dbg_event_tracing_for_windows
│           ├── ntdll_syscall_table_dump.ts # x64dbg_ntdll_syscall_table_dump
│           ├── simd_vector_differ.ts # x64dbg_simd_vector_differ
│           ├── function_prototype_generator.ts # x64dbg_function_prototype_generator
│           ├── memory_region_aliasing_detector.ts # x64dbg_memory_region_aliasing_detector
│           ├── vulkan_dx11_dx12_hook_scanner.ts # x64dbg_vulkan_dx11_dx12_hook_scanner
│           ├── gdi_user_object_inspector.ts # x64dbg_gdi_user_object_inspector
│           ├── wow64_transition_analyzer.ts # x64dbg_wow64_transition_analyzer
│           ├── hardware_breakpoint_evasion_detector.ts # x64dbg_hardware_breakpoint_evasion_detector
│           ├── import_address_table_reconstructor.ts # x64dbg_import_address_table_reconstructor
│           ├── appcontainer_isolation_auditor.ts # x64dbg_appcontainer_isolation_auditor
│           ├── com_monikers_inspector.ts # x64dbg_com_monikers_inspector
│           ├── seh_scope_table_unpacker.ts # x64dbg_seh_scope_table_unpacker
│           ├── win32k_syscall_auditor.ts # x64dbg_win32k_syscall_auditor
│           ├── seh_cxx_catch_block_mapper.ts # x64dbg_seh_cxx_catch_block_mapper
│           ├── dotnet_appdomain_memory_dumper.ts # x64dbg_dotnet_appdomain_memory_dumper
│           ├── named_pipe_impersonation_checker.ts # x64dbg_named_pipe_impersonation_checker
│           ├── fls_slot_data_walker.ts # x64dbg_fls_slot_data_walker
│           ├── dll_export_forwarder_resolver.ts # x64dbg_dll_export_forwarder_resolver
│           ├── pe_delay_load_directory_parser.ts # x64dbg_pe_delay_load_directory_parser
│           ├── com_surrogate_dcom_inspector.ts # x64dbg_com_surrogate_dcom_inspector
│           ├── string_entropy_classifier.ts # x64dbg_string_entropy_classifier
│           ├── dynamic_stub_unfolder.ts # x64dbg_dynamic_stub_unfolder
│           ├── handle_leak_detector.ts # x64dbg_handle_leak_detector
│           ├── driver_ioctl_fuzzer_harness.ts # x64dbg_driver_ioctl_fuzzer_harness
│           ├── anti_anti_debug_engine.ts # x64dbg_anti_anti_debug_engine
│           ├── stack_pivot_gadget_hunter.ts # x64dbg_stack_pivot_gadget_hunter
│           ├── instruction_cycle_profiler.ts # x64dbg_instruction_cycle_profiler
│           ├── thread_affinity_core_mapper.ts # x64dbg_thread_affinity_core_mapper
│           ├── iat_camouflaging_detector.ts # x64dbg_iat_camouflaging_detector
│           ├── page_guard_trigger_logger.ts # x64dbg_page_guard_trigger_logger
│           ├── process_mitigation_policy_viewer.ts # x64dbg_process_mitigation_policy_viewer
│           ├── etw_event_injector.ts # x64dbg_etw_event_injector
│           ├── pe_exception_directory_validator.ts # x64dbg_pe_exception_directory_validator
│           ├── crypto_key_schedule_tracer.ts # x64dbg_crypto_key_schedule_tracer
│           ├── call_graph_exporter.ts # x64dbg_call_graph_exporter
│           ├── shadow_stack_cet_validator.ts # x64dbg_shadow_stack_cet_validator
│           ├── process_environment_block_dumper.ts # x64dbg_process_environment_block_dumper
│           ├── pe_version_info_parser.ts # x64dbg_pe_version_info_parser
│           ├── memory_hexdump_differ.ts # x64dbg_memory_hexdump_differ
│           ├── rop_payload_generator.ts # x64dbg_rop_payload_generator
│           ├── veh_exception_hook_debugger.ts # x64dbg_veh_exception_hook_debugger
│           ├── nt_status_code_resolver.ts # x64dbg_nt_status_code_resolver
│           ├── branch_heatmap_exporter.ts # x64dbg_branch_heatmap_exporter
│           ├── thread_priority_quantum_auditor.ts # x64dbg_thread_priority_quantum_auditor
│           ├── memory_commit_tracker.ts # x64dbg_memory_commit_tracker
│           ├── symbolic_taint_flow_synthesizer.ts # x64dbg_symbolic_taint_flow_synthesizer
│           ├── module_export_entropy_analyzer.ts # x64dbg_module_export_entropy_analyzer
│           ├── aslr_entropy_evaluator.ts # x64dbg_aslr_entropy_evaluator
│           ├── pe_bound_import_directory_parser.ts # x64dbg_pe_bound_import_directory_parser
│           ├── pe_architecture_directory_parser.ts # x64dbg_pe_architecture_directory_parser
│           ├── pe_global_pointer_register_parser.ts # x64dbg_pe_global_pointer_register_parser
│           ├── virtual_memory_coalescing_analyzer.ts # x64dbg_virtual_memory_coalescing_analyzer
│           ├── seh_filter_expression_evaluator.ts # x64dbg_seh_filter_expression_evaluator
│           ├── thread_pool_worker_inspector.ts # x64dbg_thread_pool_worker_inspector
│           ├── fiber_local_storage_allocator.ts # x64dbg_fiber_local_storage_allocator
│           ├── com_class_factory_inspector.ts # x64dbg_com_class_factory_inspector
│           ├── ole_drag_drop_data_sniffer.ts # x64dbg_ole_drag_drop_data_sniffer
│           ├── memory_region_entropy_profiler.ts # x64dbg_memory_region_entropy_profiler
│           ├── directx_shader_bytecode_extractor.ts # x64dbg_directx_shader_bytecode_extractor
│           ├── pe_com_descriptor_parser.ts # x64dbg_pe_com_descriptor_parser
│           ├── clr_jit_code_allocator_tracer.ts # x64dbg_clr_jit_code_allocator_tracer
│           ├── wow64_fs_redirection_inspector.ts # x64dbg_wow64_fs_redirection_inspector
│           ├── win32_clipboard_data_inspector.ts # x64dbg_win32_clipboard_data_inspector
│           ├── memory_page_dirty_tracker.ts # x64dbg_memory_page_dirty_tracker
│           ├── stack_unwind_code_disassembler.ts # x64dbg_stack_unwind_code_disassembler
│           ├── dynamic_code_cave_allocator.ts # x64dbg_dynamic_code_cave_allocator
│           ├── pe_rich_header_verifier.ts # x64dbg_pe_rich_header_verifier
│           ├── nt_thread_execution_state_auditor.ts # x64dbg_nt_thread_execution_state_auditor
│           ├── pipe_message_queue_dumper.ts # x64dbg_pipe_message_queue_dumper
│           ├── fls_callback_dispatcher.ts # x64dbg_fls_callback_dispatcher
│           ├── instruction_dependency_analyzer.ts # x64dbg_instruction_dependency_analyzer
│           ├── process_tree_snapshotter.ts # x64dbg_process_tree_snapshotter
│           ├── hypervisor_vmcall_trap_detector.ts # x64dbg_hypervisor_vmcall_trap_detector
│           ├── seh_chained_unwind_handler.ts # x64dbg_seh_chained_unwind_handler
│           ├── dotnet_type_system_inspector.ts # x64dbg_dotnet_type_system_inspector
│           ├── crypto_stream_cipher_detector.ts # x64dbg_crypto_stream_cipher_detector
│           ├── dynamic_branch_predictor_simulator.ts # x64dbg_dynamic_branch_predictor_simulator
│           ├── com_interface_proxy_stub_walker.ts # x64dbg_com_interface_proxy_stub_walker
│           ├── pe_export_forwarder_chaser.ts # x64dbg_pe_export_forwarder_chaser
│           ├── memory_protection_transition_logger.ts # x64dbg_memory_protection_transition_logger
│           ├── hardware_breakpoint_counter.ts # x64dbg_hardware_breakpoint_counter
│           ├── windows_hook_chain_auditor.ts # x64dbg_windows_hook_chain_auditor
│           ├── gdi_font_resource_carver.ts # x64dbg_gdi_font_resource_carver
│           ├── appcontainer_capability_checker.ts # x64dbg_appcontainer_capability_checker
│           ├── etw_security_provider_tracer.ts # x64dbg_etw_security_provider_tracer
│           ├── symbolic_mba_rewriter.ts # x64dbg_symbolic_mba_rewriter
│           ├── instruction_prefix_validator.ts # x64dbg_instruction_prefix_validator
│           ├── thread_synchronization_wait_chain_walker.ts # x64dbg_thread_synchronization_wait_chain_walker
│           ├── pe_import_lookup_table_validator.ts # x64dbg_pe_import_lookup_table_validator
│           ├── crypto_hash_state_inspector.ts # x64dbg_crypto_hash_state_inspector
│           ├── memory_region_duplicate_scanner.ts # x64dbg_memory_region_duplicate_scanner
│           ├── process_token_group_auditor.ts # x64dbg_process_token_group_auditor
│           ├── seh_leaf_function_unwinder.ts # x64dbg_seh_leaf_function_unwinder
│           ├── driver_dispatch_table_dumper.ts # x64dbg_driver_dispatch_table_dumper
│           ├── wow64_cross_bitness_memory_reader.ts # x64dbg_wow64_cross_bitness_memory_reader
│           ├── directx_vtable_method_mapper.ts # x64dbg_directx_vtable_method_mapper
│           ├── rop_chain_disassembler.ts # x64dbg_rop_chain_disassembler
│           ├── wow64_cpu_context_reader.ts # x64dbg_wow64_cpu_context_reader
│           ├── kernel_object_security_descriptor_parser.ts # x64dbg_kernel_object_security_descriptor_parser
│           ├── seh_handler_frame_validator.ts # x64dbg_seh_handler_frame_validator
│           ├── simd_avx512_mask_register_inspector.ts # x64dbg_simd_avx512_mask_register_inspector
│           ├── pe_enclave_directory_parser.ts # x64dbg_pe_enclave_directory_parser
│           ├── pe_relocation_block_stream_dumper.ts # x64dbg_pe_relocation_block_stream_dumper
│           ├── memory_page_commit_graph_exporter.ts # x64dbg_memory_page_commit_graph_exporter
│           ├── dynamic_branch_island_allocator.ts # x64dbg_dynamic_branch_island_allocator
│           ├── thread_teb_stack_limits_verifier.ts # x64dbg_thread_teb_stack_limits_verifier
│           ├── com_aggregation_unwrapper.ts # x64dbg_com_aggregation_unwrapper
│           ├── ole_clipboard_format_enumerator.ts # x64dbg_ole_clipboard_format_enumerator
│           ├── directx_hlsl_constant_buffer_dumper.ts # x64dbg_directx_hlsl_constant_buffer_dumper
│           ├── dotnet_garbage_collection_heap_walker.ts # x64dbg_dotnet_garbage_collection_heap_walker
│           ├── win32_window_prop_inspector.ts # x64dbg_win32_window_prop_inspector
│           ├── hardware_pstate_frequency_estimator.ts # x64dbg_hardware_pstate_frequency_estimator
│           ├── instruction_fusion_analyzer.ts # x64dbg_instruction_fusion_analyzer
│           ├── process_token_privilege_adjuster.ts # x64dbg_process_token_privilege_adjuster
│           ├── fls_fiber_context_switcher.ts # x64dbg_fls_fiber_context_switcher
│           ├── hypervisor_timing_jitter_detector.ts # x64dbg_hypervisor_timing_jitter_detector
│           ├── seh_cxx_throw_info_tracer.ts # x64dbg_seh_cxx_throw_info_tracer
│           ├── crypto_asymmetric_key_detector.ts # x64dbg_crypto_asymmetric_key_detector
│           ├── memory_working_set_differ.ts # x64dbg_memory_working_set_differ
│           ├── pe_import_delay_load_unbinder.ts # x64dbg_pe_import_delay_load_unbinder
│           ├── string_table_id_lookup.ts # x64dbg_string_table_id_lookup
│           ├── process_mitigation_acg_enforcer_checker.ts # x64dbg_process_mitigation_acg_enforcer_checker
│           ├── thread_ideal_processor_assigner.ts # x64dbg_thread_ideal_processor_assigner
│           ├── etw_trace_session_enumerator.ts # x64dbg_etw_trace_session_enumerator
│           ├── rop_gadget_cluster_analyzer.ts # x64dbg_rop_gadget_cluster_analyzer
│           ├── memory_guard_page_arm_disarm.ts # x64dbg_memory_guard_page_arm_disarm
│           ├── directx_swapchain_present_counter.ts # x64dbg_directx_swapchain_present_counter
│           ├── pe_export_ordinal_name_mapper.ts # x64dbg_pe_export_ordinal_name_mapper
│           ├── gdi_dc_attribute_inspector.ts # x64dbg_gdi_dc_attribute_inspector
│           ├── symbolic_variable_range_bounder.ts # x64dbg_symbolic_variable_range_bounder
│           ├── wow64_peb32_dumper.ts # x64dbg_wow64_peb32_dumper
│           ├── named_pipe_security_checker.ts # x64dbg_named_pipe_security_checker
│           ├── crypto_aes_ni_instruction_tracer.ts # x64dbg_crypto_aes_ni_instruction_tracer
│           ├── instruction_side_effect_checker.ts # x64dbg_instruction_side_effect_checker
│           ├── appcontainer_loopback_permission_checker.ts # x64dbg_appcontainer_loopback_permission_checker
│           ├── thread_quantum_priority_booster.ts # x64dbg_thread_quantum_priority_booster
│           ├── memory_pointer_derereference_chain_tracer.ts # x64dbg_memory_pointer_derereference_chain_tracer
│           ├── seh_handler_dispatcher_sim.ts # x64dbg_seh_handler_dispatcher_sim
│           ├── dotnet_syncblk_table_inspector.ts # x64dbg_dotnet_syncblk_table_inspector
│           ├── pe_resource_manifest_parser.ts # x64dbg_pe_resource_manifest_parser
│           ├── hypervisor_cpuid_leaf_spoof_detector.ts # x64dbg_hypervisor_cpuid_leaf_spoof_detector
│           ├── driver_device_extension_dumper.ts # x64dbg_driver_device_extension_dumper
│           ├── com_class_object_rot_table_inspector.ts # x64dbg_com_class_object_rot_table_inspector
│           ├── memory_region_entropy_delta_visualizer.ts # x64dbg_memory_region_entropy_delta_visualizer
│           ├── instruction_branch_runlength_profiler.ts # x64dbg_instruction_branch_runlength_profiler
│           ├── process_handle_quota_inspector.ts # x64dbg_process_handle_quota_inspector
│           ├── pe_coff_symbol_table_parser.ts # x64dbg_pe_coff_symbol_table_parser
│           ├── vbs_hvci_detector.ts # x64dbg_vbs_hvci_detector
│           ├── indirect_syscall_analyzer.ts # x64dbg_indirect_syscall_analyzer
│           ├── ppid_spoof_detector.ts # x64dbg_ppid_spoof_detector
│           ├── process_ghosting_detector.ts # x64dbg_process_ghosting_detector
│           ├── tp_hijack_detector.ts # x64dbg_tp_hijack_detector
│           ├── format_string_analyzer.ts # x64dbg_format_string_analyzer
│           ├── vm_bytecode_mapper.ts # x64dbg_vm_bytecode_mapper
│           ├── rpc_interface_inspector.ts # x64dbg_rpc_interface_inspector
│           ├── wsl_pico_inspector.ts # x64dbg_wsl_pico_inspector
│           ├── xfg_type_hash_auditor.ts # x64dbg_xfg_type_hash_auditor
│           ├── dse_patchguard_evaluator.ts # x64dbg_dse_patchguard_evaluator
│           ├── v8_jit_inspector.ts # x64dbg_v8_jit_inspector
│           ├── corrupted_primitive_builder.ts # x64dbg_corrupted_primitive_builder
│           ├── tls_key_extractor.ts # x64dbg_tls_key_extractor
│           ├── unreal_unity_introspector.ts # x64dbg_unreal_unity_introspector
│           ├── amx_matrix_inspector.ts # x64dbg_amx_matrix_inspector
│           ├── ebpf_windows_analyzer.ts # x64dbg_ebpf_windows_analyzer
│           ├── early_apc_tracer.ts # x64dbg_early_apc_tracer
│           ├── krnl_pci_dma_auditor.ts # x64dbg_krnl_pci_dma_auditor
│           ├── rust_panic_unwinder.ts # x64dbg_rust_panic_unwinder
│           ├── golang_goid_scheduler_walker.ts # x64dbg_golang_goid_scheduler_walker
│           ├── oep_reconstructor.ts # x64dbg_oep_reconstructor
│           ├── hyperv_vmbus_inspector.ts # x64dbg_hyperv_vmbus_inspector
│           ├── kernel_handle_table_parser.ts # x64dbg_kernel_handle_table_parser
│           ├── memory_compression_decoder.ts # x64dbg_memory_compression_decoder
│           ├── lbr_branch_ring_inspector.ts # x64dbg_lbr_branch_ring_inspector
│           ├── ept_hook_detector.ts # x64dbg_ept_hook_detector
│           ├── crash_backward_slicer.ts # x64dbg_crash_backward_slicer
│           ├── inmemory_snapshot_harness.ts # x64dbg_inmemory_snapshot_harness
│           ├── alpc_ndr_fuzzer.ts # x64dbg_alpc_ndr_fuzzer
│           ├── memory_transition_flight_recorder.ts # x64dbg_memory_transition_flight_recorder
│           ├── driver_ioctl_prober.ts # x64dbg_driver_ioctl_prober
│           ├── crypto_session_harvester.ts # x64dbg_crypto_session_harvester
│           ├── mmvad_tree_explorer.ts # x64dbg_mmvad_tree_explorer
│           ├── kernel_pool_feng_shui.ts # x64dbg_kernel_pool_feng_shui
│           ├── hal_dispatch_hijack_auditor.ts # x64dbg_hal_dispatch_hijack_auditor
│           ├── lsass_dpapi_blob_reader.ts # x64dbg_lsass_dpapi_blob_reader
│           ├── ntfs_mft_artifact_carver.ts # x64dbg_ntfs_mft_artifact_carver
│           ├── kuser_shared_data_inspector.ts # x64dbg_kuser_shared_data_inspector
│           ├── wfp_callout_auditor.ts # x64dbg_wfp_callout_auditor
│           ├── ndis_lwf_chain_inspector.ts # x64dbg_ndis_lwf_chain_inspector
│           ├── prefetch_forensics_engine.ts # x64dbg_prefetch_forensics_engine
│           ├── token_impersonation_chain_walker.ts # x64dbg_token_impersonation_chain_walker
│           ├── legacy_debugger_tools.ts # x64dbg_legacy_debugger_tools
│           ├── firmware_uefi_tools.ts # x64dbg_firmware_uefi_tools
│           ├── cpu_internals_tools.ts # x64dbg_cpu_internals_tools
│           ├── kernel_structures_tools.ts # x64dbg_kernel_structures_tools
│           ├── injection_persistence_tools.ts # x64dbg_injection_persistence_tools
│           ├── network_c2_protocol_tools.ts # x64dbg_network_c2_protocol_tools
│           ├── anti_analysis_evasion_tools.ts # x64dbg_anti_analysis_evasion_tools
│           ├── memory_forensics_deep_tools.ts # x64dbg_memory_forensics_deep_tools
│           ├── binary_analysis_deep_tools.ts # x64dbg_binary_analysis_deep_tools
│           ├── com_ole_minifilter_tools.ts # x64dbg_com_ole_minifilter_tools
│           ├── crypto_forensics_threat_tools.ts # x64dbg_crypto_forensics_threat_tools
│           ├── specialized_architecture_tools.ts # x64dbg_specialized_architecture_tools
│           ├── deep_binary_virtualization_tools.ts # x64dbg_deep_binary_virtualization_tools
│           ├── gadget_semantic_builder.ts # x64dbg_gadget_semantic_builder
│           ├── indirect_resolution.ts # x64dbg_indirect_resolution
│           ├── heap_gadget_finder.ts # x64dbg_heap_gadget_finder
│           ├── symbolic_exploit_finder.ts # x64dbg_symbolic_exploit_finder
│           ├── api_dependency_graph.ts # x64dbg_api_dependency_graph
│           ├── string_decryption_automation.ts # x64dbg_string_decryption_automation
│           ├── jit_rop_analyzer.ts # x64dbg_jit_rop_analyzer
│           ├── gadget_quality_scorer.ts # x64dbg_gadget_quality_scorer
│           ├── semantic_patcher.ts # x64dbg_semantic_patcher
│           ├── binary_analysis_deep_tools.ts # x64dbg_binary_analysis_deep_tools
│           ├── calltree.ts # x64dbg_calltree
│           ├── api_logger.ts # x64dbg_api_logger
│           ├── memory_classifier.ts # x64dbg_memory_classifier
│           ├── stack_inspector.ts # x64dbg_stack_inspector
│           ├── import_forge.ts # x64dbg_import_forge
│           ├── instruction_emulator.ts # x64dbg_instruction_emulator
│           ├── branch_coverage.ts # x64dbg_branch_coverage
│           ├── hollowing_detector.ts # x64dbg_hollowing_detector
│           ├── watch.ts # x64dbg_watch
│           ├── script_engine.ts # x64dbg_script_engine
│           ├── memwatch.ts # x64dbg_memwatch
│           ├── stringxref.ts # x64dbg_stringxref
│           ├── autoannotate.ts # x64dbg_autoannotate
│
├── docs/REFERENCE.md               # This file
├── LICENSE                         # MIT
└── README.md
```

### Tech stack

**MCP Server (TypeScript)**
- **Runtime**: Node.js >= 18
- **Language**: TypeScript (ES2022, strict mode)
- **MCP SDK**: `@modelcontextprotocol/sdk` ^1.12.1
- **Validation**: `zod` ^3.25.1
- **Transport**: stdio (stdin/stdout JSON-RPC)

**Plugin (C++)**
- **Standard**: C++23
- **Compiler**: Clang-cl (ships with Visual Studio 2022)
- **Build System**: CMake 3.20+ with Ninja
- **Dependencies**: nlohmann/json (via vcpkg), x64dbg Plugin SDK, Winsock2
- **Package Manager**: vcpkg

## Building from source

### Prerequisites

CMake >= 3.20, Ninja, vcpkg (`VCPKG_ROOT` set), and Clang-cl (Visual Studio 2022 C++ workload),
plus Node.js >= 18 for the server.

The x64dbg plugin SDK import libs (`x64bridge.lib`, `x64dbg.lib`, ...) are release artifacts
that don't live in any source tree, so they're **fetched from the official x64dbg release**
rather than committed. `plugin/fetch-sdk.ps1` pulls them (headers + libs) when the local copy
is behind the latest release, and falls back to the cached SDK when offline. `build.ps1` runs
it for you.

### One-shot

```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"

.\build.ps1                 # fetch SDK + build both x64 + x32 plugins
.\build.ps1 -Arch x64       # x64 only
.\build.ps1 -Server         # also build the TypeScript server
.\build.ps1 -Install        # build, then install into x64dbg (auto-detected)
.\build.ps1 -ForceSdk       # re-download the SDK even if up to date

# Output:
#   plugin/build/x64-release/bin/x64dbg_mcp.dp64
#   plugin/build/x32-release/bin/x64dbg_mcp.dp32
```

### Manual

```powershell
.\plugin\fetch-sdk.ps1        # sync SDK headers + libs
cd plugin
cmake --preset x64-release
cmake --build --preset x64-release
cmake --preset x32-release
cmake --build --preset x32-release
```

### TypeScript server

```bash
cd server
npm install
npm run build
node dist/index.js          # run from source
```

Point your MCP client at a local build instead of npm:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "node",
      "args": ["C:/path/to/x64dbg_mcp/server/dist/index.js"]
    }
  }
}
```

### Installing the built plugin

`install.ps1` finds x64dbg automatically (shell registration → running process → PATH →
prompt, cached afterwards) and copies the DLLs into the right `plugins\` folders:

```powershell
.\install.ps1               # detect x64dbg, install both
.\install.ps1 -Arch x64     # x64 only
.\install.ps1 -Build        # build missing plugins first
.\install.ps1 -Path "D:\re\x64dbg\release"
.\install.ps1 -Force        # ignore cached path and re-detect
```

## Troubleshooting

### "Connection refused" or server can't reach plugin

1. Make sure x64dbg is running with a target loaded
2. Verify the plugin is in the correct `plugins/` directory
3. Check the x64dbg log for `[MCP] x64dbg MCP server started on 127.0.0.1:27042`
4. Test manually: `curl http://127.0.0.1:27042/api/health`

### "Waiting for x64dbg plugin..." hangs

The MCP server waits for the plugin to come online. Either:
- Start x64dbg **before** launching your MCP client
- Or restart the MCP client after x64dbg is running

### Tools return errors about debugger state

| Error | Meaning | Solution |
|-------|---------|----------|
| "Debugger must be paused" | Inspection tools need paused state | Pause the target or hit a breakpoint first |
| "No active debug session" | No executable loaded | Load a target in x64dbg (`File > Open`) |
| "Debugger must be running" | `pause`/`force_pause` need running target | Run the target first |

### 32-bit vs 64-bit

Use the correct plugin for your target architecture:

| Target | Debugger | Plugin file |
|--------|----------|-------------|
| 64-bit | x64dbg | `x64dbg_mcp.dp64` |
| 32-bit | x32dbg | `x64dbg_mcp.dp32` |

Both use the same MCP server — just `npx -y x64dbg-mcp-server`.

### Plugin not loading

1. Check that the DLL is in the right directory (e.g. `x64/plugins/` for 64-bit)
2. Make sure you're using a recent x64dbg snapshot (2024+)
3. Check if another plugin is conflicting on port 27042
4. Try manually: type `mcpserver start` in the x64dbg command bar

### "Entry point `_DllMain@12` could not be located in ...x64dbg_mcp.dp32"

This affected `x32dbg` on newer x64dbg snapshots and is fixed in **v2.2.2+**. Download the
latest `x64dbg_mcp.dp32`/`.dp64` from
[Releases](https://github.com/bromoket/x64dbg_mcp/releases) and replace the old DLLs. (Cause:
older builds lacked an explicit `DllMain` entry point that newer x64dbg loaders require.)

### Request timeouts

By default the server waits indefinitely, because debugger operations such as run/continue and
conditional traces are unbounded. For a hard ceiling (e.g. to fail fast when the plugin is
unresponsive), set a positive millisecond value:

```bash
X64DBG_MCP_TIMEOUT=120000 npx -y x64dbg-mcp-server
```

## Security

- The C++ plugin binds to `127.0.0.1` only — no remote access, no network exposure
- The MCP server communicates exclusively via stdio (stdin/stdout)
- All HTTP traffic stays on localhost — no data leaves your machine
- No permissive CORS headers are sent, so a local browser page cannot drive the debugger
- Authentication is optional (localhost-only by default). Set a token in **Settings > Token**
  and pass `X64DBG_MCP_TOKEN` to require `Authorization: Bearer <token>` on every request —
  useful to keep other local processes out
