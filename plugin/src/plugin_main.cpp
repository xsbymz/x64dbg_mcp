#include "plugin_main.h"

#include <string>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <chrono>

#include <nlohmann/json.hpp>

#include "_plugins.h"
#include "http/c_http_server.h"
#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/trace_state.h"
#include "resources/plugin_icon.h"
#include "ui/settings_dialog.h"
#include "ui/about_dialog.h"

// Forward declarations for handler registration functions
namespace handlers {
    void register_debug_routes(c_http_router& router);
    void register_register_routes(c_http_router& router);
    void register_memory_routes(c_http_router& router);
    void register_breakpoint_routes(c_http_router& router);
    void register_disasm_routes(c_http_router& router);
    void register_module_routes(c_http_router& router);
    void register_thread_routes(c_http_router& router);
    void register_stack_routes(c_http_router& router);
    void register_symbol_routes(c_http_router& router);
    void register_annotation_routes(c_http_router& router);
    void register_search_routes(c_http_router& router);
    void register_patch_routes(c_http_router& router);
    void register_memmap_routes(c_http_router& router);
    void register_command_routes(c_http_router& router);
    void register_analysis_routes(c_http_router& router);
    void register_tracing_routes(c_http_router& router);
    void register_dumping_routes(c_http_router& router);
    void register_antidebug_routes(c_http_router& router);
    void register_exception_routes(c_http_router& router);
    void register_process_routes(c_http_router& router);
    void register_handles_routes(c_http_router& router);
    void register_controlflow_routes(c_http_router& router);
    void register_shellcode_routes(c_http_router& router);
    void register_diffing_routes(c_http_router& router);
    void register_crash_routes(c_http_router& router);
    void register_peb_routes(c_http_router& router);
    void register_syscall_routes(c_http_router& router);
    void register_taint_routes(c_http_router& router);
    void register_batch_routes(c_http_router& router);
    void register_yara_routes(c_http_router& router);
    void register_heap_routes(c_http_router& router);
    void register_resource_routes(c_http_router& router);
    void register_veh_routes(c_http_router& router);
    void register_iathash_routes(c_http_router& router);
    void register_etw_amsi_routes(c_http_router& router);
    void register_primitive_routes(c_http_router& router);
    void register_config_routes(c_http_router& router);
    void register_unpacker_routes(c_http_router& router);
    void register_security_routes(c_http_router& router);
    void register_audit_routes(c_http_router& router);
    void register_session_routes(c_http_router& router);
    void register_corruption_routes(c_http_router& router);
    void register_primitive_routes(c_http_router& router);
    void register_obfuscation_routes(c_http_router& router);
    void register_control_flow_routes(c_http_router& router);
    void register_antidebug_advanced_routes(c_http_router& router);
    void register_vm_detection_routes(c_http_router& router);
    void register_fuzzing_routes(c_http_router& router);
    void register_symbolic_routes(c_http_router& router);
    void register_diffing_enhanced_routes(c_http_router& router);
    void register_kernel_routes(c_http_router& router);
    // New feature handlers
    void register_watch_routes(c_http_router& router);
    void register_script_engine_routes(c_http_router& router);
    void register_coverage_routes(c_http_router& router);
    void register_memwatch_routes(c_http_router& router);
    void register_stringxref_routes(c_http_router& router);
    void register_autoannotate_routes(c_http_router& router);
    void register_vulnhunt_routes(c_http_router& router);
    void register_calltree_routes(c_http_router& router);
    // Advanced RE & Exploit Handlers
    void register_injection_routes(c_http_router& router);
    void register_instruction_emulator_routes(c_http_router& router);
    void register_rop_advanced_routes(c_http_router& router);
    void register_stack_inspector_routes(c_http_router& router);
    void register_memory_classifier_routes(c_http_router& router);
    void register_privesc_routes(c_http_router& router);
    void register_import_forge_routes(c_http_router& router);
    void register_hollowing_routes(c_http_router& router);
    void register_string_decryption_routes(c_http_router& router);
    void register_indirect_resolution_routes(c_http_router& router);
    void register_api_logger_routes(c_http_router& router);
    void register_patch_semantic_routes(c_http_router& router);
    void register_heap_advanced_routes(c_http_router& router);
    void register_symbolic_advanced_routes(c_http_router& router);
    void register_behavior_graph_routes(c_http_router& router);
    void register_branch_coverage_routes(c_http_router& router);
    // Specification Features 11-20
    void register_behavior_chain_routes(c_http_router& router);
    void register_c2_pattern_routes(c_http_router& router);
    void register_dead_code_routes(c_http_router& router);
    void register_signature_generator_routes(c_http_router& router);
    void register_encoding_detector_routes(c_http_router& router);
    void register_compression_detector_routes(c_http_router& router);
    void register_exploit_scoring_routes(c_http_router& router);
    void register_exploit_primitives_routes(c_http_router& router);
    void register_vuln_pattern_handler_routes(c_http_router& router);
    void register_binary_diff_routes(c_http_router& router);
    void register_stack_canary_routes(c_http_router& router);
    void register_vuln_chain_routes(c_http_router& router);
    void register_code_similarity_routes(c_http_router& router);
    // Enterprise Advanced RE & Hardware Handlers
    void register_struct_reconstructor_routes(c_http_router& router);
    void register_crypto_hunter_routes(c_http_router& router);
    void register_com_rpc_routes(c_http_router& router);
    void register_hw_state_routes(c_http_router& router);
    void register_binary_triager_routes(c_http_router& router);
    // Language Runtime Forensics, IPC, Authenticode & Hotpatch Handlers
    void register_golang_routes(c_http_router& router);
    void register_dotnet_routes(c_http_router& router);
    void register_rust_routes(c_http_router& router);
    void register_ipc_routes(c_http_router& router);
    void register_cert_routes(c_http_router& router);
    void register_hotpatch_routes(c_http_router& router);
    // Advanced Auditing, Hypervisor & Flow Handlers
    void register_hook_scanner_routes(c_http_router& router);
    void register_driver_auditor_routes(c_http_router& router);
    void register_exception_tracer_routes(c_http_router& router);
    void register_hypervisor_detector_routes(c_http_router& router);
    void register_flow_visualizer_routes(c_http_router& router);
    // Extended Binary Auditing, MBA, IPC & PE Handlers (15 Handlers)
    void register_pe_overlay_routes(c_http_router& router);
    void register_delphi_routes(c_http_router& router);
    void register_token_privilege_routes(c_http_router& router);
    void register_relocation_fixer_routes(c_http_router& router);
    void register_call_convention_routes(c_http_router& router);
    void register_symbolic_evaluator_routes(c_http_router& router);
    void register_network_socket_routes(c_http_router& router);
    void register_entropy_heatmap_routes(c_http_router& router);
    void register_rich_header_routes(c_http_router& router);
    void register_file_activity_routes(c_http_router& router);
    void register_registry_activity_routes(c_http_router& router);
    void register_thread_stack_differ_routes(c_http_router& router);
    void register_vtable_dumper_routes(c_http_router& router);
    void register_module_rebaser_routes(c_http_router& router);
    void register_service_inspector_routes(c_http_router& router);
    // 36 Advanced Enterprise Debugger & RE Handlers (v4.5.0)
    void register_minidump_routes(c_http_router& router);
    void register_tls_callback_routes(c_http_router& router);
    void register_pdb_symbol_routes(c_http_router& router);
    void register_seh_unwind_routes(c_http_router& router);
    void register_rsrc_carver_routes(c_http_router& router);
    void register_typelib_routes(c_http_router& router);
    void register_clr_meta_routes(c_http_router& router);
    void register_peb_teb_adv_routes(c_http_router& router);
    void register_fiber_routes(c_http_router& router);
    void register_apc_routes(c_http_router& router);
    void register_job_routes(c_http_router& router);
    void register_pipe_intercept_routes(c_http_router& router);
    void register_alpc_routes(c_http_router& router);
    void register_string_table_routes(c_http_router& router);
    void register_exception_tester_routes(c_http_router& router);
    void register_mem_protect_routes(c_http_router& router);
    void register_heap_leak_routes(c_http_router& router);
    void register_deadlock_routes(c_http_router& router);
    void register_handle_dup_routes(c_http_router& router);
    void register_dll_hijack_routes(c_http_router& router);
    void register_entropy_delta_routes(c_http_router& router);
    void register_assembler_routes(c_http_router& router);
    void register_decoder_routes(c_http_router& router);
    void register_pe_security_routes(c_http_router& router);
    void register_debug_dir_routes(c_http_router& router);
    void register_load_config_routes(c_http_router& router);
    void register_cfg_guard_routes(c_http_router& router);
    void register_pattern_replace_routes(c_http_router& router);
    void register_str_obf_routes(c_http_router& router);
    void register_api_synth_routes(c_http_router& router);
    void register_branch_tracer_routes(c_http_router& router);
    void register_wndproc_routes(c_http_router& router);
    void register_etw_trace_routes(c_http_router& router);
    void register_ntdll_syscalls_routes(c_http_router& router);
    void register_simd_diff_routes(c_http_router& router);
    void register_proto_gen_routes(c_http_router& router);
    // 44 Ultra-Advanced RE, Forensics & Concurrency Handlers (v6.0.0)
    void register_mem_alias_routes(c_http_router& router);
    void register_gfx_hook_routes(c_http_router& router);
    void register_gdi_user_routes(c_http_router& router);
    void register_wow64_routes(c_http_router& router);
    void register_hw_evasion_routes(c_http_router& router);
    void register_iat_reconstruct_routes(c_http_router& router);
    void register_appcontainer_routes(c_http_router& router);
    void register_com_moniker_routes(c_http_router& router);
    void register_seh_scopetable_routes(c_http_router& router);
    void register_win32k_syscalls_routes(c_http_router& router);
    void register_cxx_eh_routes(c_http_router& router);
    void register_clr_domain_routes(c_http_router& router);
    void register_pipe_sec_routes(c_http_router& router);
    void register_fls_walker_routes(c_http_router& router);
    void register_export_forward_routes(c_http_router& router);
    void register_delay_load_routes(c_http_router& router);
    void register_dcom_surrogate_routes(c_http_router& router);
    void register_str_classify_routes(c_http_router& router);
    void register_stub_unfold_routes(c_http_router& router);
    void register_handle_leak_routes(c_http_router& router);
    void register_ioctl_fuzzer_routes(c_http_router& router);
    void register_stealth_routes(c_http_router& router);
    void register_pivot_hunter_routes(c_http_router& router);
    void register_cycle_profiler_routes(c_http_router& router);
    void register_thread_affinity_routes(c_http_router& router);
    void register_iat_camo_routes(c_http_router& router);
    void register_page_guard_routes(c_http_router& router);
    void register_mitigations_routes(c_http_router& router);
    void register_etw_inject_routes(c_http_router& router);
    void register_pe_ex_dir_routes(c_http_router& router);
    void register_crypto_keys_routes(c_http_router& router);
    void register_call_graph_export_routes(c_http_router& router);
    void register_cet_shadow_routes(c_http_router& router);
    void register_peb_dump_routes(c_http_router& router);
    void register_pe_version_routes(c_http_router& router);
    void register_hexdump_diff_routes(c_http_router& router);
    void register_rop_payload_routes(c_http_router& router);
    void register_veh_hook_routes(c_http_router& router);
    void register_status_resolver_routes(c_http_router& router);
    void register_branch_heatmap_routes(c_http_router& router);
    void register_thread_priority_routes(c_http_router& router);
    void register_mem_commit_routes(c_http_router& router);
    void register_taint_synth_routes(c_http_router& router);
    void register_export_entropy_routes(c_http_router& router);
    // 50 Omnipotent RE, VMM & System Internals Handlers (v7.0.0)
    void register_aslr_eval_routes(c_http_router& router);
    void register_bound_imports_routes(c_http_router& router);
    void register_arch_dir_routes(c_http_router& router);
    void register_globalptr_routes(c_http_router& router);
    void register_mem_coalesce_routes(c_http_router& router);
    void register_seh_filter_routes(c_http_router& router);
    void register_thread_pool_routes(c_http_router& router);
    void register_fls_alloc_routes(c_http_router& router);
    void register_class_factory_routes(c_http_router& router);
    void register_ole_drag_routes(c_http_router& router);
    void register_entropy_profile_routes(c_http_router& router);
    void register_shader_extract_routes(c_http_router& router);
    void register_pe_cor20_routes(c_http_router& router);
    void register_clr_jit_routes(c_http_router& router);
    void register_wow64_fs_routes(c_http_router& router);
    void register_clipboard_routes(c_http_router& router);
    void register_dirty_pages_routes(c_http_router& router);
    void register_unwind_disasm_routes(c_http_router& router);
    void register_code_cave_routes(c_http_router& router);
    void register_rich_verify_routes(c_http_router& router);
    void register_exec_state_routes(c_http_router& router);
    void register_pipe_dump_routes(c_http_router& router);
    void register_fls_cb_routes(c_http_router& router);
    void register_inst_dep_routes(c_http_router& router);
    void register_proc_tree_routes(c_http_router& router);
    void register_vmcall_trap_routes(c_http_router& router);
    void register_seh_chain_routes(c_http_router& router);
    void register_dotnet_type_routes(c_http_router& router);
    void register_stream_cipher_routes(c_http_router& router);
    void register_branch_sim_routes(c_http_router& router);
    void register_proxy_stub_routes(c_http_router& router);
    void register_forwarder_chaser_routes(c_http_router& router);
    void register_prot_log_routes(c_http_router& router);
    void register_hw_counter_routes(c_http_router& router);
    void register_win_hooks_routes(c_http_router& router);
    void register_font_carve_routes(c_http_router& router);
    void register_appcontainer_cap_routes(c_http_router& router);
    void register_etw_sec_routes(c_http_router& router);
    void register_mba_rewrite_routes(c_http_router& router);
    void register_prefix_val_routes(c_http_router& router);
    void register_wct_walk_routes(c_http_router& router);
    void register_ilt_val_routes(c_http_router& router);
    void register_hash_state_routes(c_http_router& router);
    void register_mem_dup_routes(c_http_router& router);
    void register_token_group_routes(c_http_router& router);
    void register_leaf_unwind_routes(c_http_router& router);
    void register_driver_dispatch_routes(c_http_router& router);
    void register_wow64_mem_routes(c_http_router& router);
    void register_dx_vtable_routes(c_http_router& router);
    void register_rop_disasm_routes(c_http_router& router);
    // 50 Supreme RE, System Internals & Runtime Handlers (v8.0.0)
    void register_wow64_ctx_routes(c_http_router& router);
    void register_sec_desc_routes(c_http_router& router);
    void register_seh_val_routes(c_http_router& router);
    void register_avx_mask_routes(c_http_router& router);
    void register_enclave_dir_routes(c_http_router& router);
    void register_reloc_stream_routes(c_http_router& router);
    void register_commit_graph_routes(c_http_router& router);
    void register_branch_island_routes(c_http_router& router);
    void register_teb_stack_routes(c_http_router& router);
    void register_com_aggr_routes(c_http_router& router);
    void register_ole_clip_routes(c_http_router& router);
    void register_dx_cbuffer_routes(c_http_router& router);
    void register_clr_gc_routes(c_http_router& router);
    void register_wnd_props_routes(c_http_router& router);
    void register_cpu_freq_routes(c_http_router& router);
    void register_macro_fusion_routes(c_http_router& router);
    void register_token_adjust_routes(c_http_router& router);
    void register_fiber_switch_routes(c_http_router& router);
    void register_rdtsc_jitter_routes(c_http_router& router);
    void register_cxx_throw_routes(c_http_router& router);
    void register_asym_crypto_routes(c_http_router& router);
    void register_working_set_routes(c_http_router& router);
    void register_delay_unbind_routes(c_http_router& router);
    void register_str_table_id_routes(c_http_router& router);
    void register_acg_check_routes(c_http_router& router);
    void register_ideal_proc_routes(c_http_router& router);
    void register_etw_sessions_routes(c_http_router& router);
    void register_gadget_cluster_routes(c_http_router& router);
    void register_guard_toggle_routes(c_http_router& router);
    void register_dx_present_routes(c_http_router& router);
    void register_ordinal_map_routes(c_http_router& router);
    void register_gdi_dc_routes(c_http_router& router);
    void register_range_bounds_routes(c_http_router& router);
    void register_peb32_dump_routes(c_http_router& router);
    void register_pipe_sec_desc_routes(c_http_router& router);
    void register_aesni_trace_routes(c_http_router& router);
    void register_inst_side_effects_routes(c_http_router& router);
    void register_loopback_check_routes(c_http_router& router);
    void register_boost_toggle_routes(c_http_router& router);
    void register_ptr_chain_routes(c_http_router& router);
    void register_rtl_dispatch_routes(c_http_router& router);
    void register_clr_syncblk_routes(c_http_router& router);
    void register_pe_manifest_routes(c_http_router& router);
    void register_cpuid_spoof_routes(c_http_router& router);
    void register_device_ext_routes(c_http_router& router);
    void register_rot_table_routes(c_http_router& router);
    void register_entropy_delta_svg_routes(c_http_router& router);
    void register_branch_runlength_routes(c_http_router& router);
    void register_handle_quota_routes(c_http_router& router);
    void register_coff_symbols_routes(c_http_router& router);
    // 10 Next-Gen Exploit, VBS & Subsystem Handlers
    void register_vbs_hvci_routes(c_http_router& router);
    void register_indirect_syscall_routes(c_http_router& router);
    void register_ppid_spoof_routes(c_http_router& router);
    void register_ghosting_detector_routes(c_http_router& router);
    void register_tp_hijack_routes(c_http_router& router);
    void register_xsave_avx512_routes(c_http_router& router);
    void register_format_string_routes(c_http_router& router);
    void register_vm_bytecode_routes(c_http_router& router);
    void register_rpc_interface_routes(c_http_router& router);
    void register_wsl_pico_routes(c_http_router& router);
    // 10 Next-Generation Cutting-Edge Handlers (v10.0.0)
    void register_xfg_type_auditor_routes(c_http_router& router);
    void register_cet_shadow_manipulator_routes(c_http_router& router);
    void register_intel_pt_routes(c_http_router& router);
    void register_speculative_gadget_routes(c_http_router& router);
    void register_kernel_callback_routes(c_http_router& router);
    void register_dse_evaluator_routes(c_http_router& router);
    void register_v8_jit_inspector_routes(c_http_router& router);
    void register_corrupted_primitive_routes(c_http_router& router);
    void register_tls_key_extractor_routes(c_http_router& router);
    void register_game_engine_introspector_routes(c_http_router& router);
    // 10 Ultimate RE, Kernel & Runtime Handlers (v11.0.0)
    void register_amx_matrix_routes(c_http_router& router);
    void register_ebpf_analyzer_routes(c_http_router& router);
    void register_early_apc_routes(c_http_router& router);
    void register_pci_dma_auditor_routes(c_http_router& router);
    void register_rust_panic_routes(c_http_router& router);
    void register_golang_scheduler_routes(c_http_router& router);
    void register_oep_reconstructor_routes(c_http_router& router);
    void register_vmbus_inspector_routes(c_http_router& router);
    void register_kernel_handle_table_routes(c_http_router& router);
    void register_memory_compression_routes(c_http_router& router);
    // 8 Advanced Hardware, Hypervisor, Dynamic Slicing & IPC Handlers (v12.0.0)
    void register_lbr_branch_ring_routes(c_http_router& router);
    void register_ept_hook_detector_routes(c_http_router& router);
    void register_crash_backward_slicer_routes(c_http_router& router);
    void register_inmemory_snapshot_routes(c_http_router& router);
    void register_alpc_ndr_fuzzer_routes(c_http_router& router);
    void register_memory_transition_routes(c_http_router& router);
    void register_driver_ioctl_prober_routes(c_http_router& router);
    void register_crypto_session_harvester_routes(c_http_router& router);
    // 10 Deep Recon: VAD, Pool, HAL, LSASS, NTFS, KUSD, WFP, NDIS, Prefetch & Token Tools (v13.0.0)
    void register_mmvad_tree_routes(c_http_router& router);
    void register_kernel_pool_feng_shui_routes(c_http_router& router);
    void register_hal_dispatch_routes(c_http_router& router);
    void register_lsass_dpapi_routes(c_http_router& router);
    void register_ntfs_mft_routes(c_http_router& router);
    void register_kuser_shared_routes(c_http_router& router);
    void register_wfp_callout_routes(c_http_router& router);
    void register_ndis_lwf_routes(c_http_router& router);
    void register_prefetch_forensics_routes(c_http_router& router);
    void register_token_chain_routes(c_http_router& router);
    // 44 Unconventional Low-Level, Kernel, Forensic & Threat Handlers (v14.0.0)
    void register_uefi_runtime_services_routes(c_http_router& router);
    void register_uefi_nvram_routes(c_http_router& router);
    void register_tpm_pcr_routes(c_http_router& router);
    void register_acpi_table_routes(c_http_router& router);
    void register_spi_flash_routes(c_http_router& router);
    void register_idt_hook_routes(c_http_router& router);
    void register_gdt_segment_routes(c_http_router& router);
    void register_msr_auditor_routes(c_http_router& router);
    void register_cpu_vuln_routes(c_http_router& router);
    void register_cr_register_routes(c_http_router& router);
    void register_microcode_handler_routes(c_http_router& router);
    void register_sgx_enclave_routes(c_http_router& router);
    void register_pat_mtrr_routes(c_http_router& router);
    void register_kthread_ethread_routes(c_http_router& router);
    void register_kpcr_kprcb_routes(c_http_router& router);
    void register_object_type_routes(c_http_router& router);
    void register_dkom_detector_routes(c_http_router& router);
    void register_driver_object_table_routes(c_http_router& router);
    void register_irp_inspector_routes(c_http_router& router);
    void register_shadow_ssdt_routes(c_http_router& router);
    void register_dll_notification_routes(c_http_router& router);
    void register_shim_database_routes(c_http_router& router);
    void register_com_hijacking_routes(c_http_router& router);
    void register_wmi_subscription_routes(c_http_router& router);
    void register_scheduled_task_routes(c_http_router& router);
    void register_appinit_dll_routes(c_http_router& router);
    void register_gargoyle_sleep_routes(c_http_router& router);
    void register_module_stomping_routes(c_http_router& router);
    void register_cs_beacon_routes(c_http_router& router);
    void register_named_pipe_c2_routes(c_http_router& router);
    void register_doh_detector_routes(c_http_router& router);
    void register_raw_socket_routes(c_http_router& router);
    void register_http2_frame_routes(c_http_router& router);
    void register_protobuf_decoder_routes(c_http_router& router);
    void register_heavens_gate_routes(c_http_router& router);
    void register_stack_spoofing_routes(c_http_router& router);
    void register_phantom_dll_routes(c_http_router& router);
    void register_heap_spray_detector_routes(c_http_router& router);
    void register_anti_disassembly_routes(c_http_router& router);
    void register_timing_sidechannel_routes(c_http_router& router);
    void register_eop_detector_routes(c_http_router& router);
    void register_jit_spray_routes(c_http_router& router);
    void register_uaf_detector_routes(c_http_router& router);
    void register_mem_forensics_timeline_routes(c_http_router& router);
    void register_peb_ldr_integrity_routes(c_http_router& router);
    void register_code_sig_validator_routes(c_http_router& router);
    void register_compiler_fingerprint_routes(c_http_router& router);
    void register_pdb_guid_mismatch_routes(c_http_router& router);
    void register_cfi_analyzer_routes(c_http_router& router);
    void register_bindiff_vuln_locator_routes(c_http_router& router);
    void register_eh_rop_gadget_routes(c_http_router& router);
    void register_idispatch_tracer_routes(c_http_router& router);
    void register_moniker_activation_routes(c_http_router& router);
    void register_dcom_lateral_movement_routes(c_http_router& router);
    void register_ole_storage_analyzer_routes(c_http_router& router);
    void register_minifilter_driver_routes(c_http_router& router);
    void register_volume_shadow_copy_routes(c_http_router& router);
    void register_event_log_forensics_routes(c_http_router& router);
    void register_cert_store_inspector_routes(c_http_router& router);
    void register_bcrypt_provider_routes(c_http_router& router);
    void register_rng_entropy_tester_routes(c_http_router& router);
    void register_ssl_pinning_bypass_routes(c_http_router& router);
    void register_lolbin_argument_routes(c_http_router& router);
    void register_process_ancestry_routes(c_http_router& router);
    void register_lateral_movement_routes(c_http_router& router);
    void register_loldrivers_scanner_routes(c_http_router& router);
    void register_registry_hive_routes(c_http_router& router);
    void register_mem_artifact_correlator_routes(c_http_router& router);
    void register_powershell_scriptblock_routes(c_http_router& router);
    void register_supply_chain_scanner_routes(c_http_router& router);
    // 10 Deep Hardware, Virtualization & Binary Intelligence Handlers (v15.0.0)
    void register_vmx_cap_auditor_routes(c_http_router& router);
    void register_ept_page_walker_routes(c_http_router& router);
    void register_intel_pt_packet_decoder_routes(c_http_router& router);
    void register_authenticode_leaf_parser_routes(c_http_router& router);
    void register_catalog_db_lookup_routes(c_http_router& router);
    void register_sd_dacl_evaluator_routes(c_http_router& router);
    void register_dwarf_debug_parser_routes(c_http_router& router);
    void register_rtti_graph_analyzer_routes(c_http_router& router);
    void register_alpc_endpoint_inspector_routes(c_http_router& router);
    void register_ndr_format_decoder_routes(c_http_router& router);
    // 4 Architecture & Specialized Introspection Handlers
    void register_vmcs_field_decoder_routes(c_http_router& router);
    void register_paging_walker_routes(c_http_router& router);
    void register_load_config_deep_routes(c_http_router& router);
    void register_smt_solver_bridge_routes(c_http_router& router);
} // namespace handlers

// Globals
static int g_plugin_handle = -1;
static int g_menu_handle = -1;
static HWND g_hwnd_dlg = nullptr;
static c_http_server g_server;
static c_http_router g_router;
static s_plugin_settings g_settings;

// ============================================================================
// Trace state (shared with /api/trace/status via util/trace_state.h)
// ============================================================================

static std::mutex g_trace_mutex;
static bool g_trace_active = false;
static std::string g_trace_file;

namespace mcp {

void trace_set_active(bool active, const std::string& file) {
    std::lock_guard<std::mutex> lock(g_trace_mutex);
    g_trace_active = active;
    g_trace_file = active ? file : "";
}

nlohmann::json trace_status() {
    std::lock_guard<std::mutex> lock(g_trace_mutex);
    return nlohmann::json{
        {"tracing", g_trace_active},
        {"file",    g_trace_file}
    };
}

} // namespace mcp

// x64dbg fires these on the debugger thread when a run-trace starts/stops
// (CB_STARTTRACE / CB_STOPTRACE, added in the 2026.05.27 SDK). Registered
// explicitly in plugsetup because the loader does not auto-register them by
// export name.
static void cb_start_trace(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_STARTTRACE*>(cb_info);
    mcp::trace_set_active(true, (info && info->traceFilePath) ? info->traceFilePath : "");
}

static void cb_stop_trace(CBTYPE, void*) {
    mcp::trace_set_active(false, "");
}

// ============================================================================
// Server lifecycle helper
// ============================================================================

// Apply current settings (incl. auth token) and start the server.
static std::expected<void, std::string> start_server() {
    g_server.set_auth_token(g_settings.auth_token);
    return g_server.start(g_settings.host, g_settings.port, &g_router);
}

// ============================================================================
// Menu helpers
// ============================================================================

static void update_menu_state() {
    const bool running = g_server.is_running();
    _plugin_menuentrysetchecked(g_plugin_handle, menu_start_server, running);
    _plugin_menuentrysetchecked(g_plugin_handle, menu_stop_server, !running);
}

// ============================================================================
// Settings persistence
// ============================================================================

static void load_settings() {
    char buf[256];

    if (BridgeSettingGet(SETTINGS_SECTION, SETTINGS_KEY_HOST, buf)) {
        strncpy_s(g_settings.host, buf, _TRUNCATE);
    }

    duint port_val = 0;
    if (BridgeSettingGetUint(SETTINGS_SECTION, SETTINGS_KEY_PORT, &port_val)) {
        if (port_val >= 1 && port_val <= 65535) {
            g_settings.port = static_cast<uint16_t>(port_val);
        }
    }

    duint autostart_val = 0;
    if (BridgeSettingGetUint(SETTINGS_SECTION, SETTINGS_KEY_AUTOSTART, &autostart_val)) {
        g_settings.auto_start = (autostart_val != 0);
    }

    if (BridgeSettingGet(SETTINGS_SECTION, SETTINGS_KEY_TOKEN, buf)) {
        strncpy_s(g_settings.auth_token, buf, _TRUNCATE);
    }
}

static void save_settings() {
    BridgeSettingSet(SETTINGS_SECTION, SETTINGS_KEY_HOST, g_settings.host);
    BridgeSettingSetUint(SETTINGS_SECTION, SETTINGS_KEY_PORT, g_settings.port);
    BridgeSettingSetUint(SETTINGS_SECTION, SETTINGS_KEY_AUTOSTART, g_settings.auto_start ? 1 : 0);
    BridgeSettingSet(SETTINGS_SECTION, SETTINGS_KEY_TOKEN, g_settings.auth_token);
    BridgeSettingFlush();
}

// ============================================================================
// Route registration
// ============================================================================

void register_all_routes(c_http_router& router) {
    // Health check endpoint
    router.get("/api/health", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"version", PLUGIN_VERSION_STR},
            {"plugin",  PLUGIN_NAME},
            {"status",  "ok"}
        });
    });

    // Long-poll endpoint: blocks until a debug event occurs or timeout expires.
    // GET /api/events/wait?timeout_ms=N (default 10000, max 60000)
    // Returns immediately if the debugger is already paused/stopped.
    // On event: returns {"event": true, "state": "paused|stopped|running", "event_count": N}
    // On timeout: returns {"event": false, "state": "...", "event_count": N}
    // This lets AI agents avoid polling state in a loop after calling run/step.
    router.get("/api/events/wait", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();

        auto timeout_str = req.get_query("timeout_ms", "10000");
        int timeout_ms = format_utils::safe_parse_int(timeout_str, 10000);
        if (timeout_ms < 0)     timeout_ms = 0;
        if (timeout_ms > 60000) timeout_ms = 60000;

        // Sample initial event count and state
        auto initial_events = DbgFunctions()->GetDbgEvents();
        auto initial_state  = bridge.get_state_string();

        // If already paused/stopped, return immediately — no need to wait
        if (!bridge.is_running()) {
            return s_http_response::ok({
                {"event",       false},
                {"state",       initial_state},
                {"event_count", initial_events},
                {"note",        "Debugger is already paused/stopped"}
            });
        }

        // Poll for event change (debugger paused or event counter incremented)
        constexpr int kPollIntervalMs = 20;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

        while (std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kPollIntervalMs));

            auto current_events = DbgFunctions()->GetDbgEvents();
            auto current_state  = bridge.get_state_string();

            if (!bridge.is_running() || current_events != initial_events) {
                return s_http_response::ok({
                    {"event",       true},
                    {"state",       current_state},
                    {"event_count", current_events},
                    {"prev_events", initial_events}
                });
            }
        }

        return s_http_response::ok({
            {"event",       false},
            {"state",       bridge.get_state_string()},
            {"event_count", DbgFunctions()->GetDbgEvents()},
            {"note",        "Timed out waiting for debug event"}
        });
    });

    // Process info endpoint
    router.get("/api/process/info", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid = bridge.eval_expression("$pid");
        auto peb = bridge.eval_expression("peb()");
        auto entry = bridge.eval_expression("mod.entry(0)");

        return s_http_response::ok({
            {"pid",           pid},
            {"peb",           format_utils::format_address(peb)},
            {"entry_point",   format_utils::format_address(entry)},
            {"debugger_state", bridge.get_state_string()}
        });
    });

    // Register all handler categories
    handlers::register_debug_routes(router);
    handlers::register_register_routes(router);
    handlers::register_memory_routes(router);
    handlers::register_breakpoint_routes(router);
    handlers::register_disasm_routes(router);
    handlers::register_module_routes(router);
    handlers::register_thread_routes(router);
    handlers::register_stack_routes(router);
    handlers::register_symbol_routes(router);
    handlers::register_annotation_routes(router);
    handlers::register_search_routes(router);
    handlers::register_patch_routes(router);
    handlers::register_memmap_routes(router);
    handlers::register_command_routes(router);
    handlers::register_analysis_routes(router);
    handlers::register_tracing_routes(router);
    handlers::register_dumping_routes(router);
    handlers::register_antidebug_routes(router);
    handlers::register_exception_routes(router);
    handlers::register_process_routes(router);
    handlers::register_handles_routes(router);
    handlers::register_controlflow_routes(router);
    handlers::register_shellcode_routes(router);
    handlers::register_diffing_routes(router);
    handlers::register_crash_routes(router);
    handlers::register_peb_routes(router);
    handlers::register_syscall_routes(router);
    handlers::register_taint_routes(router);
    handlers::register_batch_routes(router);
    handlers::register_yara_routes(router);
    handlers::register_heap_routes(router);
    handlers::register_resource_routes(router);
    handlers::register_veh_routes(router);
    handlers::register_iathash_routes(router);
    handlers::register_etw_amsi_routes(router);
    handlers::register_primitive_routes(router);
    handlers::register_config_routes(router);
    handlers::register_unpacker_routes(router);
    handlers::register_security_routes(router);
    handlers::register_audit_routes(router);
    handlers::register_session_routes(router);
    handlers::register_corruption_routes(router);
    handlers::register_primitive_routes(router);
    handlers::register_obfuscation_routes(router);
    handlers::register_control_flow_routes(router);
    handlers::register_antidebug_advanced_routes(router);
    handlers::register_vm_detection_routes(router);
    handlers::register_fuzzing_routes(router);
    handlers::register_symbolic_routes(router);
    handlers::register_diffing_enhanced_routes(router);
    handlers::register_kernel_routes(router);
    // New feature handlers
    handlers::register_watch_routes(router);
    handlers::register_script_engine_routes(router);
    handlers::register_coverage_routes(router);
    handlers::register_memwatch_routes(router);
    handlers::register_stringxref_routes(router);
    handlers::register_autoannotate_routes(router);
    handlers::register_vulnhunt_routes(router);
    handlers::register_calltree_routes(router);
    // Advanced RE & Exploit Handlers
    handlers::register_injection_routes(router);
    handlers::register_instruction_emulator_routes(router);
    handlers::register_rop_advanced_routes(router);
    handlers::register_stack_inspector_routes(router);
    handlers::register_memory_classifier_routes(router);
    handlers::register_privesc_routes(router);
    handlers::register_import_forge_routes(router);
    handlers::register_hollowing_routes(router);
    handlers::register_string_decryption_routes(router);
    handlers::register_indirect_resolution_routes(router);
    handlers::register_api_logger_routes(router);
    handlers::register_patch_semantic_routes(router);
    handlers::register_heap_advanced_routes(router);
    handlers::register_symbolic_advanced_routes(router);
    handlers::register_behavior_graph_routes(router);
    handlers::register_branch_coverage_routes(router);
    // Specification Features 11-20
    handlers::register_behavior_chain_routes(router);
    handlers::register_c2_pattern_routes(router);
    handlers::register_dead_code_routes(router);
    handlers::register_signature_generator_routes(router);
    handlers::register_encoding_detector_routes(router);
    handlers::register_compression_detector_routes(router);
    handlers::register_exploit_scoring_routes(router);
    handlers::register_exploit_primitives_routes(router);
    handlers::register_vuln_pattern_handler_routes(router);
    handlers::register_binary_diff_routes(router);
    handlers::register_stack_canary_routes(router);
    handlers::register_vuln_chain_routes(router);
    handlers::register_code_similarity_routes(router);
    // Enterprise Advanced RE & Hardware Handlers
    handlers::register_struct_reconstructor_routes(router);
    handlers::register_crypto_hunter_routes(router);
    handlers::register_com_rpc_routes(router);
    handlers::register_hw_state_routes(router);
    handlers::register_binary_triager_routes(router);
    // Language Runtime Forensics, IPC, Authenticode & Hotpatch Handlers
    handlers::register_golang_routes(router);
    handlers::register_dotnet_routes(router);
    handlers::register_rust_routes(router);
    handlers::register_ipc_routes(router);
    handlers::register_cert_routes(router);
    handlers::register_hotpatch_routes(router);
    // Advanced Auditing, Hypervisor & Flow Handlers
    handlers::register_hook_scanner_routes(router);
    handlers::register_driver_auditor_routes(router);
    handlers::register_exception_tracer_routes(router);
    handlers::register_hypervisor_detector_routes(router);
    handlers::register_flow_visualizer_routes(router);
    // Extended Binary Auditing, MBA, IPC & PE Handlers (15 Handlers)
    handlers::register_pe_overlay_routes(router);
    handlers::register_delphi_routes(router);
    handlers::register_token_privilege_routes(router);
    handlers::register_relocation_fixer_routes(router);
    handlers::register_call_convention_routes(router);
    handlers::register_symbolic_evaluator_routes(router);
    handlers::register_network_socket_routes(router);
    handlers::register_entropy_heatmap_routes(router);
    handlers::register_rich_header_routes(router);
    handlers::register_file_activity_routes(router);
    handlers::register_registry_activity_routes(router);
    handlers::register_thread_stack_differ_routes(router);
    handlers::register_vtable_dumper_routes(router);
    handlers::register_module_rebaser_routes(router);
    handlers::register_service_inspector_routes(router);
    // 36 Advanced Enterprise Debugger & RE Handlers (v4.5.0)
    handlers::register_minidump_routes(router);
    handlers::register_tls_callback_routes(router);
    handlers::register_pdb_symbol_routes(router);
    handlers::register_seh_unwind_routes(router);
    handlers::register_rsrc_carver_routes(router);
    handlers::register_typelib_routes(router);
    handlers::register_clr_meta_routes(router);
    handlers::register_peb_teb_adv_routes(router);
    handlers::register_fiber_routes(router);
    handlers::register_apc_routes(router);
    handlers::register_job_routes(router);
    handlers::register_pipe_intercept_routes(router);
    handlers::register_alpc_routes(router);
    handlers::register_string_table_routes(router);
    handlers::register_exception_tester_routes(router);
    handlers::register_mem_protect_routes(router);
    handlers::register_heap_leak_routes(router);
    handlers::register_deadlock_routes(router);
    handlers::register_handle_dup_routes(router);
    handlers::register_dll_hijack_routes(router);
    handlers::register_entropy_delta_routes(router);
    handlers::register_assembler_routes(router);
    handlers::register_decoder_routes(router);
    handlers::register_pe_security_routes(router);
    handlers::register_debug_dir_routes(router);
    handlers::register_load_config_routes(router);
    handlers::register_cfg_guard_routes(router);
    handlers::register_pattern_replace_routes(router);
    handlers::register_str_obf_routes(router);
    handlers::register_api_synth_routes(router);
    handlers::register_branch_tracer_routes(router);
    handlers::register_wndproc_routes(router);
    handlers::register_etw_trace_routes(router);
    handlers::register_ntdll_syscalls_routes(router);
    handlers::register_simd_diff_routes(router);
    handlers::register_proto_gen_routes(router);
    // 44 Ultra-Advanced RE, Forensics & Concurrency Handlers (v6.0.0)
    handlers::register_mem_alias_routes(router);
    handlers::register_gfx_hook_routes(router);
    handlers::register_gdi_user_routes(router);
    handlers::register_wow64_routes(router);
    handlers::register_hw_evasion_routes(router);
    handlers::register_iat_reconstruct_routes(router);
    handlers::register_appcontainer_routes(router);
    handlers::register_com_moniker_routes(router);
    handlers::register_seh_scopetable_routes(router);
    handlers::register_win32k_syscalls_routes(router);
    handlers::register_cxx_eh_routes(router);
    handlers::register_clr_domain_routes(router);
    handlers::register_pipe_sec_routes(router);
    handlers::register_fls_walker_routes(router);
    handlers::register_export_forward_routes(router);
    handlers::register_delay_load_routes(router);
    handlers::register_dcom_surrogate_routes(router);
    handlers::register_str_classify_routes(router);
    handlers::register_stub_unfold_routes(router);
    handlers::register_handle_leak_routes(router);
    handlers::register_ioctl_fuzzer_routes(router);
    handlers::register_stealth_routes(router);
    handlers::register_pivot_hunter_routes(router);
    handlers::register_cycle_profiler_routes(router);
    handlers::register_thread_affinity_routes(router);
    handlers::register_iat_camo_routes(router);
    handlers::register_page_guard_routes(router);
    handlers::register_mitigations_routes(router);
    handlers::register_etw_inject_routes(router);
    handlers::register_pe_ex_dir_routes(router);
    handlers::register_crypto_keys_routes(router);
    handlers::register_call_graph_export_routes(router);
    handlers::register_cet_shadow_routes(router);
    handlers::register_peb_dump_routes(router);
    handlers::register_pe_version_routes(router);
    handlers::register_hexdump_diff_routes(router);
    handlers::register_rop_payload_routes(router);
    handlers::register_veh_hook_routes(router);
    handlers::register_status_resolver_routes(router);
    handlers::register_branch_heatmap_routes(router);
    handlers::register_thread_priority_routes(router);
    handlers::register_mem_commit_routes(router);
    handlers::register_taint_synth_routes(router);
    handlers::register_export_entropy_routes(router);
    // 50 Omnipotent RE, VMM & System Internals Handlers (v7.0.0)
    handlers::register_aslr_eval_routes(router);
    handlers::register_bound_imports_routes(router);
    handlers::register_arch_dir_routes(router);
    handlers::register_globalptr_routes(router);
    handlers::register_mem_coalesce_routes(router);
    handlers::register_seh_filter_routes(router);
    handlers::register_thread_pool_routes(router);
    handlers::register_fls_alloc_routes(router);
    handlers::register_class_factory_routes(router);
    handlers::register_ole_drag_routes(router);
    handlers::register_entropy_profile_routes(router);
    handlers::register_shader_extract_routes(router);
    handlers::register_pe_cor20_routes(router);
    handlers::register_clr_jit_routes(router);
    handlers::register_wow64_fs_routes(router);
    handlers::register_clipboard_routes(router);
    handlers::register_dirty_pages_routes(router);
    handlers::register_unwind_disasm_routes(router);
    handlers::register_code_cave_routes(router);
    handlers::register_rich_verify_routes(router);
    handlers::register_exec_state_routes(router);
    handlers::register_pipe_dump_routes(router);
    handlers::register_fls_cb_routes(router);
    handlers::register_inst_dep_routes(router);
    handlers::register_proc_tree_routes(router);
    handlers::register_vmcall_trap_routes(router);
    handlers::register_seh_chain_routes(router);
    handlers::register_dotnet_type_routes(router);
    handlers::register_stream_cipher_routes(router);
    handlers::register_branch_sim_routes(router);
    handlers::register_proxy_stub_routes(router);
    handlers::register_forwarder_chaser_routes(router);
    handlers::register_prot_log_routes(router);
    handlers::register_hw_counter_routes(router);
    handlers::register_win_hooks_routes(router);
    handlers::register_font_carve_routes(router);
    handlers::register_appcontainer_cap_routes(router);
    handlers::register_etw_sec_routes(router);
    handlers::register_mba_rewrite_routes(router);
    handlers::register_prefix_val_routes(router);
    handlers::register_wct_walk_routes(router);
    handlers::register_ilt_val_routes(router);
    handlers::register_hash_state_routes(router);
    handlers::register_mem_dup_routes(router);
    handlers::register_token_group_routes(router);
    handlers::register_leaf_unwind_routes(router);
    handlers::register_driver_dispatch_routes(router);
    handlers::register_wow64_mem_routes(router);
    handlers::register_dx_vtable_routes(router);
    handlers::register_rop_disasm_routes(router);
    // 50 Supreme RE, System Internals & Runtime Handlers (v8.0.0)
    handlers::register_wow64_ctx_routes(router);
    handlers::register_sec_desc_routes(router);
    handlers::register_seh_val_routes(router);
    handlers::register_avx_mask_routes(router);
    handlers::register_enclave_dir_routes(router);
    handlers::register_reloc_stream_routes(router);
    handlers::register_commit_graph_routes(router);
    handlers::register_branch_island_routes(router);
    handlers::register_teb_stack_routes(router);
    handlers::register_com_aggr_routes(router);
    handlers::register_ole_clip_routes(router);
    handlers::register_dx_cbuffer_routes(router);
    handlers::register_clr_gc_routes(router);
    handlers::register_wnd_props_routes(router);
    handlers::register_cpu_freq_routes(router);
    handlers::register_macro_fusion_routes(router);
    handlers::register_token_adjust_routes(router);
    handlers::register_fiber_switch_routes(router);
    handlers::register_rdtsc_jitter_routes(router);
    handlers::register_cxx_throw_routes(router);
    handlers::register_asym_crypto_routes(router);
    handlers::register_working_set_routes(router);
    handlers::register_delay_unbind_routes(router);
    handlers::register_str_table_id_routes(router);
    handlers::register_acg_check_routes(router);
    handlers::register_ideal_proc_routes(router);
    handlers::register_etw_sessions_routes(router);
    handlers::register_gadget_cluster_routes(router);
    handlers::register_guard_toggle_routes(router);
    handlers::register_dx_present_routes(router);
    handlers::register_ordinal_map_routes(router);
    handlers::register_gdi_dc_routes(router);
    handlers::register_range_bounds_routes(router);
    handlers::register_peb32_dump_routes(router);
    handlers::register_pipe_sec_desc_routes(router);
    handlers::register_aesni_trace_routes(router);
    handlers::register_inst_side_effects_routes(router);
    handlers::register_loopback_check_routes(router);
    handlers::register_boost_toggle_routes(router);
    handlers::register_ptr_chain_routes(router);
    handlers::register_rtl_dispatch_routes(router);
    handlers::register_clr_syncblk_routes(router);
    handlers::register_pe_manifest_routes(router);
    handlers::register_cpuid_spoof_routes(router);
    handlers::register_device_ext_routes(router);
    handlers::register_rot_table_routes(router);
    handlers::register_entropy_delta_svg_routes(router);
    handlers::register_branch_runlength_routes(router);
    handlers::register_handle_quota_routes(router);
    handlers::register_coff_symbols_routes(router);
    // 10 Next-Gen Exploit, VBS & Subsystem Handlers
    handlers::register_vbs_hvci_routes(router);
    handlers::register_indirect_syscall_routes(router);
    handlers::register_ppid_spoof_routes(router);
    handlers::register_ghosting_detector_routes(router);
    handlers::register_tp_hijack_routes(router);
    handlers::register_xsave_avx512_routes(router);
    handlers::register_format_string_routes(router);
    handlers::register_vm_bytecode_routes(router);
    handlers::register_rpc_interface_routes(router);
    handlers::register_wsl_pico_routes(router);
    // 10 Next-Generation Cutting-Edge Handlers (v10.0.0)
    handlers::register_xfg_type_auditor_routes(router);
    handlers::register_cet_shadow_manipulator_routes(router);
    handlers::register_intel_pt_routes(router);
    handlers::register_speculative_gadget_routes(router);
    handlers::register_kernel_callback_routes(router);
    handlers::register_dse_evaluator_routes(router);
    handlers::register_v8_jit_inspector_routes(router);
    handlers::register_corrupted_primitive_routes(router);
    handlers::register_tls_key_extractor_routes(router);
    handlers::register_game_engine_introspector_routes(router);
    // 10 Ultimate RE, Kernel & Runtime Handlers (v11.0.0)
    handlers::register_amx_matrix_routes(router);
    handlers::register_ebpf_analyzer_routes(router);
    handlers::register_early_apc_routes(router);
    handlers::register_pci_dma_auditor_routes(router);
    handlers::register_rust_panic_routes(router);
    handlers::register_golang_scheduler_routes(router);
    handlers::register_oep_reconstructor_routes(router);
    handlers::register_vmbus_inspector_routes(router);
    handlers::register_kernel_handle_table_routes(router);
    handlers::register_memory_compression_routes(router);
    // 8 Advanced Hardware, Hypervisor, Dynamic Slicing & IPC Handlers (v12.0.0)
    handlers::register_lbr_branch_ring_routes(router);
    handlers::register_ept_hook_detector_routes(router);
    handlers::register_crash_backward_slicer_routes(router);
    handlers::register_inmemory_snapshot_routes(router);
    handlers::register_alpc_ndr_fuzzer_routes(router);
    handlers::register_memory_transition_routes(router);
    handlers::register_driver_ioctl_prober_routes(router);
    handlers::register_crypto_session_harvester_routes(router);
    // 10 Deep Recon: VAD, Pool, HAL, LSASS, NTFS, KUSD, WFP, NDIS, Prefetch & Token Tools (v13.0.0)
    handlers::register_mmvad_tree_routes(router);
    handlers::register_kernel_pool_feng_shui_routes(router);
    handlers::register_hal_dispatch_routes(router);
    handlers::register_lsass_dpapi_routes(router);
    handlers::register_ntfs_mft_routes(router);
    handlers::register_kuser_shared_routes(router);
    handlers::register_wfp_callout_routes(router);
    handlers::register_ndis_lwf_routes(router);
    handlers::register_prefetch_forensics_routes(router);
    handlers::register_token_chain_routes(router);
    // 44 Unconventional Low-Level, Kernel, Forensic & Threat Handlers (v14.0.0)
    handlers::register_uefi_runtime_services_routes(router);
    handlers::register_uefi_nvram_routes(router);
    handlers::register_tpm_pcr_routes(router);
    handlers::register_acpi_table_routes(router);
    handlers::register_spi_flash_routes(router);
    handlers::register_idt_hook_routes(router);
    handlers::register_gdt_segment_routes(router);
    handlers::register_msr_auditor_routes(router);
    handlers::register_cpu_vuln_routes(router);
    handlers::register_cr_register_routes(router);
    handlers::register_microcode_handler_routes(router);
    handlers::register_sgx_enclave_routes(router);
    handlers::register_pat_mtrr_routes(router);
    handlers::register_kthread_ethread_routes(router);
    handlers::register_kpcr_kprcb_routes(router);
    handlers::register_object_type_routes(router);
    handlers::register_dkom_detector_routes(router);
    handlers::register_driver_object_table_routes(router);
    handlers::register_irp_inspector_routes(router);
    handlers::register_shadow_ssdt_routes(router);
    handlers::register_dll_notification_routes(router);
    handlers::register_shim_database_routes(router);
    handlers::register_com_hijacking_routes(router);
    handlers::register_wmi_subscription_routes(router);
    handlers::register_scheduled_task_routes(router);
    handlers::register_appinit_dll_routes(router);
    handlers::register_gargoyle_sleep_routes(router);
    handlers::register_module_stomping_routes(router);
    handlers::register_cs_beacon_routes(router);
    handlers::register_named_pipe_c2_routes(router);
    handlers::register_doh_detector_routes(router);
    handlers::register_raw_socket_routes(router);
    handlers::register_http2_frame_routes(router);
    handlers::register_protobuf_decoder_routes(router);
    handlers::register_heavens_gate_routes(router);
    handlers::register_stack_spoofing_routes(router);
    handlers::register_phantom_dll_routes(router);
    handlers::register_heap_spray_detector_routes(router);
    handlers::register_anti_disassembly_routes(router);
    handlers::register_timing_sidechannel_routes(router);
    handlers::register_eop_detector_routes(router);
    handlers::register_jit_spray_routes(router);
    handlers::register_uaf_detector_routes(router);
    handlers::register_mem_forensics_timeline_routes(router);
    handlers::register_peb_ldr_integrity_routes(router);
    handlers::register_code_sig_validator_routes(router);
    handlers::register_compiler_fingerprint_routes(router);
    handlers::register_pdb_guid_mismatch_routes(router);
    handlers::register_cfi_analyzer_routes(router);
    handlers::register_bindiff_vuln_locator_routes(router);
    handlers::register_eh_rop_gadget_routes(router);
    handlers::register_idispatch_tracer_routes(router);
    handlers::register_moniker_activation_routes(router);
    handlers::register_dcom_lateral_movement_routes(router);
    handlers::register_ole_storage_analyzer_routes(router);
    handlers::register_minifilter_driver_routes(router);
    handlers::register_volume_shadow_copy_routes(router);
    handlers::register_event_log_forensics_routes(router);
    handlers::register_cert_store_inspector_routes(router);
    handlers::register_bcrypt_provider_routes(router);
    handlers::register_rng_entropy_tester_routes(router);
    handlers::register_ssl_pinning_bypass_routes(router);
    handlers::register_lolbin_argument_routes(router);
    handlers::register_process_ancestry_routes(router);
    handlers::register_lateral_movement_routes(router);
    handlers::register_loldrivers_scanner_routes(router);
    handlers::register_registry_hive_routes(router);
    handlers::register_mem_artifact_correlator_routes(router);
    handlers::register_powershell_scriptblock_routes(router);
    handlers::register_supply_chain_scanner_routes(router);
    // 10 Deep Hardware, Virtualization & Binary Intelligence Handlers (v15.0.0)
    handlers::register_vmx_cap_auditor_routes(router);
    handlers::register_ept_page_walker_routes(router);
    handlers::register_intel_pt_packet_decoder_routes(router);
    handlers::register_authenticode_leaf_parser_routes(router);
    handlers::register_catalog_db_lookup_routes(router);
    handlers::register_sd_dacl_evaluator_routes(router);
    handlers::register_dwarf_debug_parser_routes(router);
    handlers::register_rtti_graph_analyzer_routes(router);
    handlers::register_alpc_endpoint_inspector_routes(router);
    handlers::register_ndr_format_decoder_routes(router);
    // 4 Architecture & Specialized Introspection Handlers
    handlers::register_vmcs_field_decoder_routes(router);
    handlers::register_paging_walker_routes(router);
    handlers::register_load_config_deep_routes(router);
    handlers::register_smt_solver_bridge_routes(router);
}

// ============================================================================
// MCP Server command handler
// ============================================================================

static bool mcp_server_command(int argc, char* argv[]) {
    if (argc < 2) {
        _plugin_logputs("[MCP] Usage: mcpserver <start|stop|status>");
        return false;
    }

    std::string subcommand = argv[1];

    if (subcommand == "start") {
        if (g_server.is_running()) {
            _plugin_logputs("[MCP] Server is already running");
            return true;
        }

        auto result = start_server();
        if (result.has_value()) {
            _plugin_logprintf("[MCP] Server started on %s:%u\n", g_settings.host, g_settings.port);
        } else {
            _plugin_logprintf("[MCP] Failed to start server: %s\n", result.error().c_str());
        }
        update_menu_state();
        return result.has_value();
    }

    if (subcommand == "stop") {
        if (!g_server.is_running()) {
            _plugin_logputs("[MCP] Server is not running");
            return true;
        }

        g_server.stop();
        _plugin_logputs("[MCP] Server stopped");
        update_menu_state();
        return true;
    }

    if (subcommand == "status") {
        if (g_server.is_running()) {
            _plugin_logprintf("[MCP] Server is running on %s:%u\n", g_settings.host, g_server.get_port());
        } else {
            _plugin_logputs("[MCP] Server is not running");
        }
        return true;
    }

    _plugin_logputs("[MCP] Unknown subcommand. Usage: mcpserver <start|stop|status>");
    return false;
}

// ============================================================================
// Plugin exports
// ============================================================================

// Explicit DLL entry point. Without this the 32-bit build (clang-cl) does not
// emit a resolvable _DllMain@12 symbol, and newer x64dbg snapshots refuse to
// load x64dbg_mcp.dp32 with "entry point _DllMain@12 could not be located"
// (GitHub issue #1). Defining DllMain ourselves guarantees a valid entry point
// for both x32 and x64 and is the minimum every x64dbg plugin must provide.
BOOL WINAPI DllMain(HINSTANCE /*inst*/, DWORD /*reason*/, LPVOID /*reserved*/) {
    return TRUE;
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* init_struct) {
    init_struct->sdkVersion = PLUG_SDKVERSION;
    init_struct->pluginVersion = PLUGIN_VERSION;
    strncpy_s(init_struct->pluginName, PLUGIN_NAME, _TRUNCATE);

    g_plugin_handle = init_struct->pluginHandle;

    // Register the mcpserver command
    _plugin_registercommand(g_plugin_handle, "mcpserver", mcp_server_command, false);

    // Trace lifecycle callbacks (no-op on x64dbg versions that don't fire them).
    // These are not auto-registered by export name, so register explicitly.
    _plugin_registercallback(g_plugin_handle, CB_STARTTRACE, cb_start_trace);
    _plugin_registercallback(g_plugin_handle, CB_STOPTRACE, cb_stop_trace);

    return true;
}

PLUG_EXPORT bool plugstop() {
    // Unregister command + callbacks
    _plugin_unregistercommand(g_plugin_handle, "mcpserver");
    _plugin_unregistercallback(g_plugin_handle, CB_STARTTRACE);
    _plugin_unregistercallback(g_plugin_handle, CB_STOPTRACE);

    // Stop the HTTP server
    g_server.stop();

    _plugin_logputs("[MCP] Plugin stopped");
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setup_struct) {
    // Store GUI handles
    g_hwnd_dlg = setup_struct->hwndDlg;
    g_menu_handle = setup_struct->hMenu;

    // Load persisted settings
    load_settings();

    // Set plugin menu icon
    ICONDATA icon_data;
    icon_data.data = plugin_icon::png_data;
    icon_data.size = plugin_icon::png_size;
    _plugin_menuseticon(g_menu_handle, &icon_data);

    // Build menu entries
    _plugin_menuaddentry(g_menu_handle, menu_start_server, "Start Server");
    _plugin_menuaddentry(g_menu_handle, menu_stop_server, "Stop Server");
    _plugin_menuaddseparator(g_menu_handle);
    _plugin_menuaddentry(g_menu_handle, menu_settings, "Settings...");
    _plugin_menuaddentry(g_menu_handle, menu_about, "About...");

    // Register all API routes
    register_all_routes(g_router);

    // Auto-start the server (if enabled in settings)
    if (g_settings.auto_start) {
        auto result = start_server();
        if (result.has_value()) {
            _plugin_logprintf("[MCP] x64dbg MCP Server started on %s:%u\n",
                g_settings.host, g_settings.port);
        } else {
            _plugin_logprintf("[MCP] Failed to auto-start server: %s\n", result.error().c_str());
            _plugin_logputs("[MCP] Use 'mcpserver start' to retry");
        }
    } else {
        _plugin_logputs("[MCP] Auto-start disabled. Use 'mcpserver start' or menu to start.");
    }

    // Sync checkmarks with actual server state
    update_menu_state();
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE, void* call_info) {
    auto* info = static_cast<PLUG_CB_MENUENTRY*>(call_info);

    switch (info->hEntry) {
    case menu_start_server:
        if (g_server.is_running()) {
            _plugin_logputs("[MCP] Server is already running");
        } else {
            auto result = start_server();
            if (result.has_value()) {
                _plugin_logprintf("[MCP] Server started on %s:%u\n",
                    g_settings.host, g_settings.port);
            } else {
                _plugin_logprintf("[MCP] Failed to start server: %s\n", result.error().c_str());
            }
        }
        update_menu_state();
        break;

    case menu_stop_server:
        if (!g_server.is_running()) {
            _plugin_logputs("[MCP] Server is not running");
        } else {
            g_server.stop();
            _plugin_logputs("[MCP] Server stopped");
        }
        update_menu_state();
        break;

    case menu_settings: {
        // Snapshot current settings in case we need to detect host/port changes
        const auto old_host = std::string(g_settings.host);
        const auto old_port = g_settings.port;

        if (show_settings_dialog(g_hwnd_dlg, g_settings) == IDOK) {
            save_settings();
            _plugin_logputs("[MCP] Settings saved");

            // Restart server if host/port changed and server is running
            const bool host_changed = (old_host != g_settings.host);
            const bool port_changed = (old_port != g_settings.port);

            if (g_server.is_running() && (host_changed || port_changed)) {
                g_server.stop();
                auto result = start_server();
                if (result.has_value()) {
                    _plugin_logprintf("[MCP] Server restarted on %s:%u\n",
                        g_settings.host, g_settings.port);
                } else {
                    _plugin_logprintf("[MCP] Failed to restart server: %s\n",
                        result.error().c_str());
                }
                update_menu_state();
            }
        }
        break;
    }

    case menu_about:
        show_about_dialog(g_hwnd_dlg, g_server.is_running(),
            g_settings.host, g_server.get_port());
        break;

    default:
        break;
    }
}
