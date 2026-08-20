# TypeScript API Documentation Coverage Analysis

## 1. TypeScript Surface Summary

### Entry Points
- `server/src/index.ts` — MCP server entry point, registers all tools/resources/prompts, stdio transport
- `server/src/config.ts` — Environment variable configuration (`X64DBG_MCP_*`)
- `server/src/http_client.ts` — HTTP client with auto-reconnect, health checks, retry logic
- `server/src/tools/index.ts` — Master tool registry; exports `registerAllTools(server: McpServer)`
- `server/src/resources/` — MCP dynamic resources (`x64dbg://...`)
- `server/src/prompts/` — MCP prompt templates

### Tool Registration Pattern
Each tool file exports a `register*Tools(server: McpServer)` function that calls `server.tool(name, description, zodSchema, handler)`. The master `registerAllTools` in `tools/index.ts` wires all categories into the MCP server.

### Counts
- TypeScript tool registrations: **309**
- TypeScript tool files: **~280+**
- Tool categories in `tools/index.ts`: **~60+ grouped imports**

---

## 2. README Documentation Coverage

### README.md (root)
- **Status**: Missing from current filesystem snapshot, but earlier read showed 402 lines
- **Documented tools**: ~250+ across 12 categories
- **Coverage style**: High-level category tables with action lists and one-line descriptions
- **Gaps**: Lacks per-tool parameter details, lacks newer v9–v15 specialized tools, no code examples for most tools

### server/README.md
- **Status**: Present
- **Documented tools**: 23 action-based tools
- **Coverage style**: Brief action lists, minimal parameter detail
- **Gaps**: Severely undercounts actual tool surface; describes v2.3.0-era tool set

### docs/REFERENCE.md
- **Status**: Present, 635 lines
- **Documented tools**: ~300 in categorized tables
- **Coverage style**: Exhaustive tables with actions and descriptions
- **Gaps**: Still missing some newer tools; no parameter-level docs; no usage examples

---

## 3. Gap Analysis

### A. Fully Documented (README + REFERENCE.md)
These tool groups have clear category-level coverage in both README.md and docs/REFERENCE.md:
- `x64dbg_debug` — run/pause/step/state/wait_event
- `x64dbg_registers` — get_all/get_specific/get_flags/get_avx512/set
- `x64dbg_memory` — read/write/info/allocate/protect/map/read_batch/follow_pointers/struct_view/rwx_audit/injected_check/compare_sections
- `x64dbg_disassembly` — at_address/function/range/info/assemble
- `x64dbg_breakpoints` — set_software/set_hardware/set_memory/delete/enable/disable/toggle/set_condition/set_log/reset_hit_count/get/list/configure/configure_batch
- `x64dbg_stack` — arguments/get_call_stack/read/pointers/seh_chain/return_address/comment
- `x64dbg_threads` — list/current/count/contexts_all/info/teb/name/switch/suspend/resume/context/context_set
- `x64dbg_process` — basic/detailed/cmdline/elevated/dbversion/set_cmdline
- `x64dbg_handles` — list_handles/list_tcp/list_windows/list_heaps/get_name/close
- `x64dbg_peb` — full/ldr/cmdline/env/teb_full
- `x64dbg_syscalls` — ntdll/ssn/hooks/kernel32
- `x64dbg_symbols` — resolve/address/search/list_module/get_label/set_label/get_comment/set_comment/bookmark
- `x64dbg_search` — pattern/string/xor_scan/string_at/symbol_auto_complete/encode_type
- `x64dbg_patches` — list/apply/restore/export
- `x64dbg_dumping` — pe_header/sections/imports/exports/entry_point/relocations/dump_module/fix_iat/export_patch_file
- `x64dbg_tracing` — into/over/run/stop/status/animate/conditional_run/log_setup/hitcount/type/set_type
- `x64dbg_exceptions` — set/delete/list/list_codes/skip/seh_chain
- `x64dbg_yara` — from_memory/from_behavior
- `x64dbg_heap` — list/walk/corruption
- `x64dbg_taint` — mark/clear/status/trace_step
- `x64dbg_shellcode` — execute/disassemble
- `x64dbg_antidebug` — audit/hooks/peb/teb/dep/hide_debugger
- `x64dbg_vm` — detect/registry_artifacts/driver_check/cpuid_check
- `x64dbg_crash` — triage/buckets/last
- `x64dbg_audit` — log/stats/clear
- `x64dbg_session` — save/restore/list/delete
- `x64dbg_security` — status/verify_token/hardening_report
- `x64dbg_batch` — batch request array
- `x64dbg_fuzz` — harness/iterate/crash_triage/coverage/stop
- `x64dbg_symbolic` — constraints/solve/taint_propagation/path_exploration
- `x64dbg_diffing_enhanced` — semantic/patch_analysis
- `x64dbg_kernel` — token_steal_check/pool_overflow_detection/callbacks
- `x64dbg_obfuscation` — detect/vm_detect/string_decrypt/opaque_predicates/flattening/loops/branch_analysis/indirect_calls
- `x64dbg_antidebug_advanced` — timing_checks/hardware_bp_detection/ntquery_hooks/exception_handlers
- `x64dbg_primitives_advanced` — arbitrary_read/arbitrary_write/info_leak/stack_pivot
- `x64dbg_corruption` — stack_canary/format_string/heap_overflow/uaf_candidates
- `x64dbg_etw_amsi` — detect ETW/AMSI bypass
- `x64dbg_iathash` — iat/eat
- `x64dbg_resources` — list/extract
- `x64dbg_veh` — VEH chain enumeration
- `x64dbg_diffing` — memory_vs_disk/pe_sections/patches
- `x64dbg_unpacker` — auto/entry_candidates
- `x64dbg_config` — extract/strings
- `x64dbg_snapshot` — create/diff/list
- `x64dbg_telemetry` — enable/disable
- `x64dbg_gui` — windows
- `x64dbg_control_flow` — cfg/branch_dest/is_jump_taken/loops/func_type/add_function/delete_function
- `x64dbg_analysis` — function/xrefs_to/xrefs_from/basic_blocks/source/mnemonic_brief/entropy/rop_gadgets/rop_gadgets_advanced/rop_chain_builder/vtable/vtable_rtti/dataflow
- `x64dbg_etw_trace` — ETW session enumeration
- `x64dbg_privesc` — token privilege inspection
- `x64dbg_hollowing` — process hollowing detection

### B. Partially Documented (mentioned but missing parameter/action detail)
These appear in README/REFERENCE but lack full parameter-level documentation:
- `x64dbg_rop_builder` — README mentions actions but not full Zod schema details (find_gadgets/build_chain/validate_chain/export_chain)
- `x64dbg_api_logger` — mentioned in REFERENCE but not in README
- `x64dbg_injection` — mentioned in REFERENCE but not in README
- `x64dbg_memory_classifier` — mentioned in REFERENCE but not in README
- `x64dbg_stack_inspector` — mentioned in REFERENCE but not in README
- `x64dbg_import_forge` — mentioned in REFERENCE but not in README
- `x64dbg_instruction_emulator` — mentioned in REFERENCE but not in README
- `x64dbg_branch_coverage` — mentioned in REFERENCE but not in README
- `x64dbg_hollowing_detector` — mentioned in REFERENCE but not in README
- `x64dbg_watch` — mentioned in REFERENCE but not in README
- `x64dbg_script_engine` — mentioned in REFERENCE but not in README
- `x64dbg_coverage` — mentioned in REFERENCE but not in README
- `x64dbg_memwatch` — mentioned in REFERENCE but not in README
- `x64dbg_stringxref` — mentioned in REFERENCE but not in README
- `x64dbg_autoannotate` — mentioned in REFERENCE but not in README

### C. Undocumented in README (present in TypeScript but missing from README)
These are registered in `tools/index.ts` and have `.ts` implementations but are **not listed** in README.md:

#### New Feature Tools (Tier 1–3)
- `x64dbg_gadget_semantic_builder` — semantic gadget synthesis
- `x64dbg_indirect_resolution` — indirect call/vtable/switch resolution
- `x64dbg_heap_gadget_finder` — heap exploitation gadget discovery
- `x64dbg_symbolic_exploit_finder` — SMT-guided crash path exploration
- `x64dbg_api_dependency_graph` — API call dependency mapping
- `x64dbg_string_decryption_automation` — automated multi-algorithm string decryption
- `x64dbg_jit_rop_analyzer` — JIT ROP gadget analysis
- `x64dbg_gadget_quality_scorer` — gadget reliability scoring
- `x64dbg_semantic_patcher` — intent-based patching
- `x64dbg_calltree` — N-level call tree generator
- `x64dbg_behavior_chain_extractor` — temporal action chain extraction
- `x64dbg_c2_pattern_analyzer` — C2 beaconing analysis
- `x64dbg_dead_code_analyzer` — dead code detection
- `x64dbg_signature_generator` — YARA/Sigma/Snort generation
- `x64dbg_encoding_detector` — multi-alphabet decoding
- `x64dbg_compression_detector` — compressed stream detection
- `x64dbg_exploit_likelihood_scorer` — composite exploitability scoring
- `x64dbg_vuln_chain_discoverer` — multi-stage exploit chain synthesis
- `x64dbg_code_similarity_engine` — CFG isomorphism + fuzzy hashing
- `x64dbg_struct_reconstructor` — C/C++ struct reconstruction
- `x64dbg_crypto_hunter` — crypto lookup table scanner
- `x64dbg_com_rpc_walker` — COM VTable/RPC mapper
- `x64dbg_hw_state_inspector` — DR0-DR7/CET/AVX-512 state
- `x64dbg_binary_triager` — one-shot binary security triage
- `x64dbg_golang_helper` — Go runtime recovery
- `x64dbg_dotnet_helper` — CLR version detection
- `x64dbg_rust_helper` — Rust symbol demangling
- `x64dbg_ipc_monitor` — Named Pipes/Mailslots/Shared Sections
- `x64dbg_cert_authenticode` — Authenticode verification
- `x64dbg_hotpatch_engine` — live function hooking
- `x64dbg_hook_scanner` — user-mode hook scanner
- `x64dbg_driver_auditor` — kernel driver inspector
- `x64dbg_exception_tracer` — KiUserExceptionDispatcher tracer
- `x64dbg_hypervisor_detector` — VM detection
- `x64dbg_flow_visualizer` — Mermaid/Graphviz flowcharts
- `x64dbg_pe_overlay_analyzer` — PE overlay carver
- `x64dbg_delphi_helper` — Delphi VMT inspector
- `x64dbg_token_privilege_auditor` — token privilege auditor
- `x64dbg_relocation_fixer` — .reloc rebasing
- `x64dbg_call_convention_inferrer` — calling convention inference
- `x64dbg_symbolic_evaluator` — MBA simplifier
- `x64dbg_network_socket_tracker` — TCP/UDP socket tracker
- `x64dbg_entropy_heatmap` — entropy heatmap exporter
- `x64dbg_rich_header_analyzer` — Rich PE header decryption
- `x64dbg_file_activity_tracer` — filesystem activity tracer
- `x64dbg_registry_activity_tracer` — registry tracer
- `x64dbg_thread_stack_differ` — multi-thread stack diff
- `x64dbg_vtable_dumper` — C++ VTable dumper
- `x64dbg_module_rebaser` — module base shift simulator
- `x64dbg_service_inspector` — Windows Service inspector
- `x64dbg_minidump_generator` — full/mini dump generator
- `x64dbg_tls_callback_analyzer` — TLS callback inspector
- `x64dbg_pdb_symbol_downloader` — PDB downloader
- `x64dbg_seh_unwind_table_parser` — .pdata/.xdata parser
- `x64dbg_resource_payload_carver` — embedded PE/RCDATA carver
- `x64dbg_com_type_library_parser` — ITypeLib decompiler
- `x64dbg_dotnet_metadata_tables` — .NET metadata parser
- `x64dbg_peb_teb_advanced` — FastPebLocks/FLS/ActiveFrame
- `x64dbg_fls_fiber_inspector` — Fiber/FLS inspector
- `x64dbg_apc_queue_inspector` — APC queue inspector
- `x64dbg_job_object_inspector` — Job Object inspector
- `x64dbg_pipe_data_interceptor` — Named Pipe interceptor
- `x64dbg_rpc_alpc_inspector` — ALPC/RPC inspector
- `x64dbg_string_table_extractor` — String Table extractor
- `x64dbg_exception_filter_tester` — synthetic exception injector
- `x64dbg_memory_permission_watcher` — VirtualProtect transition logger
- `x64dbg_heap_leak_detector` — heap leak detector
- `x64dbg_deadlock_detector` — deadlock detector
- `x64dbg_handle_duplicator` — handle duplication/elevation
- `x64dbg_dll_hijack_auditor` — DLL search order auditor
- `x64dbg_entropy_delta_monitor` — entropy shift tracker
- `x64dbg_x86_x64_assembler` — raw assembler
- `x64dbg_instruction_decoder` — machine code decoder
- `x64dbg_pe_security_directory` — WIN_CERTIFICATE parser
- `x64dbg_debug_directory_parser` — CodeView/POGO parser
- `x64dbg_load_config_directory` — IMAGE_LOAD_CONFIG_DIRECTORY64 parser
- `x64dbg_cfg_guard_table_checker` — CFG bitmap checker
- `x64dbg_memory_pattern_replacer` — pattern search/replace
- `x64dbg_string_obfuscation_detector` — stack string/XOR table detector
- `x64dbg_api_call_synthesizer` — in-memory API execution
- `x64dbg_branch_target_tracer` — branch destination tracer
- `x64dbg_window_message_logger` — WndProc message logger
- `x64dbg_event_tracing_for_windows` — ETW session querier
- `x64dbg_ntdll_syscall_table_dump` — syscall table dumper
- `x64dbg_simd_vector_differ` — SIMD vector differ
- `x64dbg_function_prototype_generator` — prototype synthesizer
- `x64dbg_memory_region_aliasing_detector` — COW/shared-section detector
- `x64dbg_vulkan_dx11_dx12_hook_scanner` — graphics hook scanner
- `x64dbg_gdi_user_object_inspector` — USER/GDI object enumerator
- `x64dbg_wow64_transition_analyzer` — Heaven's Gate analyzer
- `x64dbg_hardware_breakpoint_evasion_detector` — DR clearing detector
- `x64dbg_import_address_table_reconstructor` — IAT reconstructor
- `x64dbg_appcontainer_isolation_auditor` — AppContainer auditor
- `x64dbg_com_monikers_inspector` — COM Moniker inspector
- `x64dbg_seh_scope_table_unpacker` — SEH ScopeTable parser
- `x64dbg_win32k_syscall_auditor` — win32k syscall auditor
- `x64dbg_seh_cxx_catch_block_mapper` — C++ EH mapper
- `x64dbg_dotnet_appdomain_memory_dumper` — AppDomain memory dumper
- `x64dbg_named_pipe_impersonation_checker` — impersonation checker
- `x64dbg_fls_slot_data_walker` — FLS slot walker
- `x64dbg_dll_export_forwarder_resolver` — export forwarder resolver
- `x64dbg_pe_delay_load_directory_parser` — delay-load parser
- `x64dbg_com_surrogate_dcom_inspector` — DCOM surrogate inspector
- `x64dbg_string_entropy_classifier` — string classifier
- `x64dbg_dynamic_stub_unfolder` — opaque jump stub unfolder
- `x64dbg_handle_leak_detector` — handle leak detector
- `x64dbg_driver_ioctl_fuzzer_harness` — IOCTL fuzzer harness
- `x64dbg_anti_anti_debug_engine` — anti-anti-debug engine
- `x64dbg_stack_pivot_gadget_hunter` — stack pivot hunter
- `x64dbg_instruction_cycle_profiler` — RDTSC cycle profiler
- `x64dbg_thread_affinity_core_mapper` — affinity mapper
- `x64dbg_iat_camouflaging_detector` — IAT camouflage detector
- `x64dbg_page_guard_trigger_logger` — PAGE_GUARD logger
- `x64dbg_process_mitigation_policy_viewer` — mitigation policy viewer
- `x64dbg_etw_event_injector` — ETW event injector
- `x64dbg_pe_exception_directory_validator` — exception directory validator
- `x64dbg_crypto_key_schedule_tracer` — key schedule tracer
- `x64dbg_call_graph_exporter` — call graph exporter
- `x64dbg_shadow_stack_cet_validator` — CET shadow stack validator
- `x64dbg_process_environment_block_dumper` — PEB/RTL_USER_PROCESS_PARAMETERS dumper
- `x64dbg_pe_version_info_parser` — VS_VERSIONINFO parser
- `x64dbg_memory_hexdump_differ` — hex dump differ
- `x64dbg_rop_payload_generator` — ROP payload generator
- `x64dbg_veh_exception_hook_debugger` — VEH hook debugger
- `x64dbg_nt_status_code_resolver` — NTSTATUS resolver
- `x64dbg_branch_heatmap_exporter` — branch heatmap exporter
- `x64dbg_thread_priority_quantum_auditor` — priority/quantum auditor
- `x64dbg_memory_commit_tracker` — commit tracker
- `x64dbg_symbolic_taint_flow_synthesizer` — taint flow synthesizer
- `x64dbg_module_export_entropy_analyzer` — export entropy analyzer
- `x64dbg_aslr_entropy_evaluator` — ASLR entropy evaluator
- `x64dbg_pe_bound_import_directory_parser` — bound import parser
- `x64dbg_pe_architecture_directory_parser` — architecture directory parser
- `x64dbg_pe_global_pointer_register_parser` — global pointer parser
- `x64dbg_virtual_memory_coalescing_analyzer` — coalescing analyzer
- `x64dbg_seh_filter_expression_evaluator` — SEH filter evaluator
- `x64dbg_thread_pool_worker_inspector` — thread pool inspector
- `x64dbg_fiber_local_storage_allocator` — FLS allocator
- `x64dbg_com_class_factory_inspector` — class factory inspector
- `x64dbg_ole_drag_drop_data_sniffer` — OLE drag/drop sniffer
- `x64dbg_memory_region_entropy_profiler` — entropy profiler
- `x64dbg_directx_shader_bytecode_extractor` — shader extractor
- `x64dbg_pe_com_descriptor_parser` — COM descriptor parser
- `x64dbg_clr_jit_code_allocator_tracer` — JIT allocator tracer
- `x64dbg_wow64_fs_redirection_inspector` — WOW64 FS redirector
- `x64dbg_win32_clipboard_data_inspector` — clipboard inspector
- `x64dbg_memory_page_dirty_tracker` — dirty page tracker
- `x64dbg_stack_unwind_code_disassembler` — UNWIND_CODE disassembler
- `x64dbg_dynamic_code_cave_allocator` — code cave allocator
- `x64dbg_pe_rich_header_verifier` — Rich header verifier
- `x64dbg_nt_thread_execution_state_auditor` — execution state auditor
- `x64dbg_pipe_message_queue_dumper` — pipe message dumper
- `x64dbg_fls_callback_dispatcher` — FLS callback dispatcher
- `x64dbg_instruction_dependency_analyzer` — instruction dependency analyzer
- `x64dbg_process_tree_snapshotter` — process tree snapshotter
- `x64dbg_hypervisor_vmcall_trap_detector` — VMCALL trap detector
- `x64dbg_seh_chained_unwind_handler` — chained unwind handler
- `x64dbg_dotnet_type_system_inspector` — type system inspector
- `x64dbg_crypto_stream_cipher_detector` — stream cipher detector
- `x64dbg_dynamic_branch_predictor_simulator` — branch predictor simulator
- `x64dbg_com_interface_proxy_stub_walker` — proxy/stub walker
- `x64dbg_pe_export_forwarder_chaser` — export forwarder chaser
- `x64dbg_memory_protection_transition_logger` — protection transition logger
- `x64dbg_hardware_breakpoint_counter` — hardware BP counter
- `x64dbg_windows_hook_chain_auditor` — hook chain auditor
- `x64dbg_gdi_font_resource_carver` — font carver
- `x64dbg_appcontainer_capability_checker` — capability checker
- `x64dbg_etw_security_provider_tracer` — ETW security tracer
- `x64dbg_symbolic_mba_rewriter` — MBA rewriter
- `x64dbg_instruction_prefix_validator` — prefix validator
- `x64dbg_thread_synchronization_wait_chain_walker` — wait chain walker
- `x64dbg_pe_import_lookup_table_validator` — ILT validator
- `x64dbg_crypto_hash_state_inspector` — hash state inspector
- `x64dbg_memory_region_duplicate_scanner` — duplicate scanner
- `x64dbg_process_token_group_auditor` — token group auditor
- `x64dbg_seh_leaf_function_unwinder` — leaf function unwinder
- `x64dbg_driver_dispatch_table_dumper` — dispatch table dumper
- `x64dbg_wow64_cross_bitness_memory_reader` — cross-bitness reader
- `x64dbg_directx_vtable_method_mapper` — DX VTable mapper
- `x64dbg_rop_chain_disassembler` — ROP chain disassembler
- `x64dbg_wow64_cpu_context_reader` — WOW64 CPU context reader
- `x64dbg_kernel_object_security_descriptor_parser` — security descriptor parser
- `x64dbg_seh_handler_frame_validator` — SEH frame validator
- `x64dbg_simd_avx512_mask_register_inspector` — AVX-512 mask inspector
- `x64dbg_pe_enclave_directory_parser` — SGX enclave parser
- `x64dbg_pe_relocation_block_stream_dumper` — relocation stream dumper
- `x64dbg_memory_page_commit_graph_exporter` — commit graph exporter
- `x64dbg_dynamic_branch_island_allocator` — branch island allocator
- `x64dbg_thread_teb_stack_limits_verifier` — TEB/stack limits verifier
- `x64dbg_com_aggregation_unwrapper` — COM aggregation unwrapper
- `x64dbg_ole_clipboard_format_enumerator` — clipboard format enumerator
- `x64dbg_directx_hlsl_constant_buffer_dumper` — HLSL CB dumper
- `x64dbg_dotnet_garbage_collection_heap_walker` — GC heap walker
- `x64dbg_win32_window_prop_inspector` — window prop inspector
- `x64dbg_hardware_pstate_frequency_estimator` — P-state estimator
- `x64dbg_instruction_fusion_analyzer` — macro fusion analyzer
- `x64dbg_process_token_privilege_adjuster` — token privilege adjuster
- `x64dbg_fls_fiber_context_switcher` — fiber context switcher
- `x64dbg_hypervisor_timing_jitter_detector` — timing jitter detector
- `x64dbg_seh_cxx_throw_info_tracer` — C++ ThrowInfo tracer
- `x64dbg_crypto_asymmetric_key_detector` — asymmetric key detector
- `x64dbg_memory_working_set_differ` — working set differ
- `x64dbg_pe_import_delay_load_unbinder` — delay-load unbinder
- `x64dbg_string_table_id_lookup` — string table ID lookup
- `x64dbg_process_mitigation_acg_enforcer_checker` — ACG checker
- `x64dbg_thread_ideal_processor_assigner` — ideal processor assigner
- `x64dbg_etw_trace_session_enumerator` — ETW session enumerator
- `x64dbg_rop_gadget_cluster_analyzer` — gadget cluster analyzer
- `x64dbg_memory_guard_page_arm_disarm` — guard page arm/disarm
- `x64dbg_directx_swapchain_present_counter` — SwapChain present counter
- `x64dbg_pe_export_ordinal_name_mapper` — ordinal/name mapper
- `x64dbg_gdi_dc_attribute_inspector` — DC attribute inspector
- `x64dbg_symbolic_variable_range_bounder` — variable range bounter
- `x64dbg_wow64_peb32_dumper` — PEB32 dumper
- `x64dbg_named_pipe_security_checker` — named pipe security checker
- `x64dbg_crypto_aes_ni_instruction_tracer` — AES-NI tracer
- `x64dbg_instruction_side_effect_checker` — side effect checker
- `x64dbg_appcontainer_loopback_permission_checker` — loopback checker
- `x64dbg_thread_quantum_priority_booster` — quantum/priority booster
- `x64dbg_memory_pointer_derereference_chain_tracer` — pointer chain tracer
- `x64dbg_seh_handler_dispatcher_sim` — RtlDispatchException simulator
- `x64dbg_dotnet_syncblk_table_inspector` — SyncBlockTable inspector
- `x64dbg_pe_resource_manifest_parser` — manifest parser
- `x64dbg_hypervisor_cpuid_leaf_spoof_detector` — CPUID spoof detector
- `x64dbg_driver_device_extension_dumper` — device extension dumper
- `x64dbg_com_class_object_rot_table_inspector` — ROT table inspector
- `x64dbg_memory_region_entropy_delta_visualizer` — entropy delta visualizer
- `x64dbg_instruction_branch_runlength_profiler` — branch runlength profiler
- `x64dbg_process_handle_quota_inspector` — handle quota inspector
- `x64dbg_pe_coff_symbol_table_parser` — COFF symbol parser
- `x64dbg_vbs_hvci_detector` — VBS/HVCI inspector
- `x64dbg_indirect_syscall_analyzer` — indirect syscall analyzer
- `x64dbg_ppid_spoof_detector` — PPID spoof detector
- `x64dbg_process_ghosting_detector` — process ghosting detector
- `x64dbg_tp_hijack_detector` — thread pool hijack detector
- `x64dbg_xsave_avx512_inspector` — XSAVE/AVX-512 inspector
- `x64dbg_format_string_analyzer` — format string vulnerability analyzer
- `x64dbg_vm_bytecode_mapper` — VM bytecode mapper
- `x64dbg_rpc_interface_inspector` — RPC interface inspector
- `x64dbg_wsl_pico_inspector` — WSL/Pico provider inspector
- `x64dbg_xfg_type_hash_auditor` — XFG type hash auditor
- `x64dbg_cet_shadow_stack_manipulator` — CET shadow stack manipulator
- `x64dbg_intel_pt_tracer` — Intel PT tracer
- `x64dbg_speculative_gadget_hunter` — speculative gadget hunter
- `x64dbg_kernel_callback_auditor` — kernel callback auditor
- `x64dbg_dse_patchguard_evaluator` — DSE/PatchGuard evaluator
- `x64dbg_v8_jit_inspector` — V8 JIT object inspector
- `x64dbg_corrupted_primitive_builder` — corrupted primitive builder
- `x64dbg_tls_key_extractor` — TLS key extractor
- `x64dbg_unreal_unity_introspector` — Unreal/Unity introspector
- `x64dbg_amx_matrix_inspector` — AMX matrix inspector
- `x64dbg_ebpf_windows_analyzer` — eBPF Windows analyzer
- `x64dbg_early_apc_tracer` — early APC tracer
- `x64dbg_krnl_pci_dma_auditor` — PCI DMA auditor
- `x64dbg_rust_panic_unwinder` — Rust panic unwinder
- `x64dbg_golang_goid_scheduler_walker` — Go scheduler walker
- `x64dbg_oep_reconstructor` — OEP reconstructor
- `x64dbg_hyperv_vmbus_inspector` — Hyper-V VMBus inspector
- `x64dbg_kernel_handle_table_parser` — kernel handle table parser
- `x64dbg_memory_compression_decoder` — memory compression decoder
- `x64dbg_lbr_branch_ring_inspector` — LBR branch ring inspector
- `x64dbg_ept_hook_detector` — EPT hook detector
- `x64dbg_crash_backward_slicer` — crash backward slicer
- `x64dbg_inmemory_snapshot_harness` — in-memory snapshot harness
- `x64dbg_alpc_ndr_fuzzer` — ALPC NDR fuzzer
- `x64dbg_memory_transition_flight_recorder` — memory transition recorder
- `x64dbg_driver_ioctl_prober` — IOCTL prober
- `x64dbg_crypto_session_harvester` — crypto session harvester
- `x64dbg_mmvad_tree_explorer` — MMVAD tree explorer
- `x64dbg_kernel_pool_feng_shui` — kernel pool feng shui
- `x64dbg_hal_dispatch_hijack_auditor` — HAL dispatch auditor
- `x64dbg_lsass_dpapi_blob_reader` — LSASS DPAPI reader
- `x64dbg_ntfs_mft_artifact_carver` — NTFS MFT carver
- `x64dbg_kuser_shared_data_inspector` — KUSER_SHARED_DATA inspector
- `x64dbg_wfp_callout_auditor` — WFP callout auditor
- `x64dbg_ndis_lwf_chain_inspector` — NDIS LWF chain inspector
- `x64dbg_prefetch_forensics_engine` — Prefetch forensics engine
- `x64dbg_token_impersonation_chain_walker` — token impersonation chain walker
- `x64dbg_uefi_runtime_services` — UEFI runtime services
- `x64dbg_uefi_nvram` — UEFI NVRAM
- `x64dbg_tpm_pcr` — TPM PCR
- `x64dbg_acpi_table` — ACPI table
- `x64dbg_spi_flash` — SPI flash
- `x64dbg_idt_hook` — IDT hook detector
- `x64dbg_gdt_segment` — GDT/segment auditor
- `x64dbg_msr_auditor` — MSR auditor
- `x64dbg_cpu_vuln` — CPU vulnerability
- `x64dbg_cr_register` — CR register auditor
- `x64dbg_microcode_handler` — microcode handler
- `x64dbg_sgx_enclave` — SGX enclave
- `x64dbg_pat_mtrr` — PAT/MTRR
- `x64dbg_kthread_ethread` — KTHREAD/ETHREAD
- `x64dbg_kpcr_kprcb` — KPCR/KPRCB
- `x64dbg_object_type` — Object Type
- `x64dbg_dkom_detector` — DKOM detector
- `x64dbg_driver_object_table` — Driver Object table
- `x64dbg_irp_inspector` — IRP inspector
- `x64dbg_shadow_ssdt` — Shadow SSDT
- `x64dbg_dll_notification` — DLL notification
- `x64dbg_shim_database` — Shim database
- `x64dbg_com_hijacking` — COM hijacking
- `x64dbg_wmi_subscription` — WMI subscription
- `x64dbg_scheduled_task` — scheduled task
- `x64dbg_appinit_dll` — AppInit DLL
- `x64dbg_gargoyle_sleep` — gargoyle sleep
- `x64dbg_module_stomping` — module stomping
- `x64dbg_cs_beacon` — Cobalt Strike beacon
- `x64dbg_named_pipe_c2` — named pipe C2
- `x64dbg_doh_detector` — DoH detector
- `x64dbg_raw_socket` — raw socket
- `x64dbg_http2_frame` — HTTP/2 frame
- `x64dbg_protobuf_decoder` — protobuf decoder
- `x64dbg_heavens_gate` — Heaven's Gate
- `x64dbg_stack_spoofing` — stack spoofing
- `x64dbg_phantom_dll` — phantom DLL
- `x64dbg_heap_spray_detector` — heap spray detector
- `x64dbg_anti_disassembly` — anti-disassembly
- `x64dbg_timing_sidechannel` — timing side-channel
- `x64dbg_eop_detector` — EOP detector
- `x64dbg_jit_spray` — JIT spray
- `x64dbg_uaf_detector` — UAF detector
- `x64dbg_mem_forensics_timeline` — memory forensics timeline
- `x64dbg_peb_ldr_integrity` — PEB.Ldr integrity
- `x64dbg_code_sig_validator` — code signature validator
- `x64dbg_compiler_fingerprint` — compiler fingerprint
- `x64dbg_pdb_guid_mismatch` — PDB GUID mismatch
- `x64dbg_cfi_analyzer` — CFI analyzer
- `x64dbg_bindiff_vuln_locator` — BinDiff vuln locator
- `x64dbg_eh_rop_gadget` — EH ROP gadget
- `x64dbg_idispatch_tracer` — IDispatch tracer
- `x64dbg_moniker_activation` — moniker activation
- `x64dbg_dcom_lateral_movement` — DCOM lateral movement
- `x64dbg_ole_storage_analyzer` — OLE storage analyzer
- `x64dbg_minifilter_driver` — minifilter driver
- `x64dbg_volume_shadow_copy` — volume shadow copy
- `x64dbg_event_log_forensics` — event log forensics
- `x64dbg_cert_store_inspector` — certificate store inspector
- `x64dbg_bcrypt_provider` — BCrypt provider
- `x64dbg_rng_entropy_tester` — RNG entropy tester
- `x64dbg_ssl_pinning_bypass` — SSL pinning bypass
- `x64dbg_lolbin_argument` — LOLBin argument
- `x64dbg_process_ancestry` — process ancestry
- `x64dbg_lateral_movement` — lateral movement
- `x64dbg_loldrivers_scanner` — LOLDrivers scanner
- `x64dbg_registry_hive` — registry hive
- `x64dbg_mem_artifact_correlator` — memory artifact correlator
- `x64dbg_powershell_scriptblock` — PowerShell ScriptBlock
- `x64dbg_supply_chain_scanner` — supply chain scanner
- `x64dbg_vmx_cap_auditor` — VMX capabilities auditor
- `x64dbg_ept_page_walker` — EPT page walker
- `x64dbg_intel_pt_packet_decoder` — Intel PT packet decoder
- `x64dbg_authenticode_leaf_parser` — Authenticode leaf parser
- `x64dbg_catalog_db_lookup` — catalog DB lookup
- `x64dbg_sd_dacl_evaluator` — SDDL/DACL evaluator
- `x64dbg_dwarf_debug_parser` — DWARF debug parser
- `x64dbg_rtti_graph_analyzer` — RTTI graph analyzer
- `x64dbg_alpc_endpoint_inspector` — ALPC endpoint inspector
- `x64dbg_ndr_format_decoder` — NDR format decoder
- `x64dbg_vmcs_field_decoder` — VMCS field decoder
- `x64dbg_paging_walker` — paging walker
- `x64dbg_load_config_deep` — deep LoadConfig parser
- `x64dbg_smt_solver_bridge` — SMT-LIB2 solver bridge

### D. Completely Missing from Both README and REFERENCE
These tool files exist in `server/src/tools/` but are **not indexed** in either README.md or docs/REFERENCE.md:
- `binary_analysis_deep_tools.ts`
- `deep_binary_virtualization_tools.ts`
- `cpu_internals_tools.ts`
- `kernel_structures_tools.ts`
- `injection_persistence_tools.ts`
- `network_c2_protocol_tools.ts`
- `anti_analysis_evasion_tools.ts`
- `memory_forensics_deep_tools.ts`
- `legacy_debugger_tools.ts`
- `firmware_uefi_tools.ts`
- `specialized_architecture_tools.ts`

---

## 4. Recommended Documentation Additions

### A. README.md additions (high-level usage snippets)

#### New Tools Section (add after "Tools at a glance")
```markdown
### Advanced Exploit & Kernel Tools

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_rop_builder` | `find_gadgets`, `build_chain`, `validate_chain`, `export_chain` | Build executable ROP chains from discovered gadgets with quality scoring and multi-format export. |
| `x64dbg_gadget_semantic_builder` | *(see docs/REFERENCE.md)* | Constraint-based semantic gadget synthesis. |
| `x64dbg_heap_gadget_finder` | *(see docs/REFERENCE.md)* | Segment heap & NT heap exploitation primitives. |
| `x64dbg_symbolic_exploit_finder` | *(see docs/REFERENCE.md)* | SMT constraint-guided crash path exploration. |
| `x64dbg_exploit_likelihood_scorer` | *(see docs/REFERENCE.md)* | Composite exploitability probability scoring. |
| `x64dbg_vuln_chain_discoverer` | *(see docs/REFERENCE.md)* | Multi-stage exploit chain synthesizer. |
| `x64dbg_kernel` | `token_steal_check`, `pool_overflow_detection`, `callbacks` | Kernel-mode exploitation helpers. |
```

#### New Section: Hardware & Virtualization
```markdown
### Hardware Tracing & CET

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_intel_pt_tracer` | `status`, `decode_trace`, `export_coverage_bitmap` | Intel Processor Trace hardware execution decoder. |
| `x64dbg_cet_shadow_stack_manipulator` | `read_shadow_stack`, `audit_ssp_tokens`, `scan_endbr_violations` | CET shadow stack and IBT validator. |
| `x64dbg_speculative_gadget_hunter` | *(see docs/REFERENCE.md)* | Speculative execution gadget discovery. |
| `x64dbg_vmx_cap_auditor` | *(see docs/REFERENCE.md)* | Intel VMX MSR auditor. |
| `x64dbg_ept_walk_simulate` | *(see docs/REFERENCE.md)* | EPT paging walk simulator. |
```

#### New Section: Deep Forensics & Kernel Internals
```markdown
### Deep Forensics & Kernel Internals

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_mmvad_tree_explorer` | *(see docs/REFERENCE.md)* | MMVAD tree explorer for VAD-based forensics. |
| `x64dbg_kernel_pool_feng_shui` | *(see docs/REFERENCE.md)* | Kernel pool layout analysis and chunk grooming. |
| `x64dbg_lsass_dpapi_blob_reader` | *(see docs/REFERENCE.md)* | LSASS DPAPI blob reader. |
| `x64dbg_ntfs_mft_artifact_carver` | *(see docs/REFERENCE.md)* | NTFS MFT artifact carver. |
| `x64dbg_kernel_callback_auditor` | *(see docs/REFERENCE.md)* | Kernel callback enumeration and integrity check. |
| `x64dbg_dkom_detector` | *(see docs/REFERENCE.md)* | DKOM hidden process/driver detector. |
```

### B. docs/REFERENCE.md additions (parameter-level details)

Add a new section after "Tool reference (300 mega-tools)":

```markdown
## Tool Reference Addendum: Advanced & Specialized Tools

### Exploit Development Advanced

| Tool | Actions | Parameters | Description |
|------|---------|------------|-------------|
| `x64dbg_rop_builder` | `find_gadgets` | `effect`, `module?`, `max_results?` | Search gadgets by desired effect |
| `x64dbg_rop_builder` | `build_chain` | `gadgets[]`, `target?` | Construct ROP chain from gadget list |
| `x64dbg_rop_builder` | `validate_chain` | `chain_address`, `chain_length?` | Validate chain in memory |
| `x64dbg_rop_builder` | `export_chain` | `gadgets[]`, `format?`, `include_args?` | Export as asm/c/python/c_shellcode |

### Hardware Tracing

| Tool | Actions | Parameters | Description |
|------|---------|------------|-------------|
| `x64dbg_intel_pt_tracer` | `status` | — | Check Intel PT status |
| `x64dbg_intel_pt_tracer` | `decode_trace` | — | Decode raw Intel PT packets |
| `x64dbg_intel_pt_tracer` | `export_coverage_bitmap` | — | Export AFL++ coverage bitmap |

### Kernel Internals

| Tool | Actions | Parameters | Description |
|------|---------|------------|-------------|
| `x64dbg_kernel_callback_auditor` | *(see source)* | — | Enumerate kernel callbacks |
| `x64dbg_kernel_handle_table_parser` | *(see source)* | — | Parse kernel handle tables |
| `x64dbg_kernel_pool_feng_shui` | *(see source)* | — | Kernel pool layout analysis |
```

### C. Quick-Reference Table: Undocumented Tools by Category

| Category | Count | Documented in README | Documented in REFERENCE |
|----------|-------|---------------------|------------------------|
| Core debugger/CPU/memory | ~40 | ✅ | ✅ |
| Stack/SEH/threads | ~20 | ✅ | ✅ |
| Disassembly/analysis | ~30 | ✅ | ✅ |
| Breakpoints/tracing | ~15 | ✅ | ✅ |
| Symbols/search | ~15 | ✅ | ✅ |
| PE/internals | ~40 | ✅ | ✅ |
| Anti-debug/VM | ~15 | ✅ | ✅ |
| Exploit primitives | ~20 | Partial | Partial |
| Malware/forensics | ~40 | Partial | Partial |
| Kernel security | ~25 | ❌ | Partial |
| Hardware/Virtualization | ~20 | ❌ | ❌ |
| Deep forensics | ~25 | ❌ | ❌ |
| Specialized architecture | ~10 | ❌ | ❌ |

---

## 5. Summary

1. **README.md** covers the core ~250 tools at category level but is missing most v9–v15 specialized tools
2. **docs/REFERENCE.md** is the most complete reference (~300 tools) but still lacks parameter-level detail for newer additions
3. **server/README.md** is severely outdated (23 tools, v2.3.0)
4. **11 tool files** are completely unindexed in any documentation
5. **Parameter-level documentation** is absent across all docs — only high-level action lists exist
6. **Usage examples** are sparse outside the main README

### Priority Fixes
1. Update `server/README.md` to reflect actual v2.6.0 tool count
2. Add missing v9–v15 tools to `docs/REFERENCE.md`
3. Add parameter-level docs for `x64dbg_rop_builder`, `x64dbg_intel_pt_tracer`, `x64dbg_cet_shadow_stack_manipulator`
4. Create a dedicated `ADVANCED_TOOLS.md` for the ~90 specialized tools not in README
5. Add usage examples for top 20 advanced tools
