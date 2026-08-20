import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAntiAnalysisEvasionTools(server: McpServer) {
  // Heaven's Gate
  server.tool('x64dbg_heavens_gate_detect', 'Detect 32-bit to 64-bit WOW64 Heaven\'s Gate far jumps (CS 0x33).', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/heavens_gate/detect_far_jumps', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_heavens_gate_analyze_wow64', 'Analyze WOW64 mode switch mechanisms and TEB64 access.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/heavens_gate/analyze_wow64_transitions', {}), null, 2) }] };
  });
  server.tool('x64dbg_heavens_gate_scan_syscalls', 'Scan for direct 64-bit SYSCALL instructions in 32-bit process.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/heavens_gate/scan_for_direct_syscalls', { pid: pid ?? 0 }), null, 2) }] };
  });

  // Stack Spoofing
  server.tool('x64dbg_stack_spoof_validate', 'Validate thread call stacks against .pdata UNWIND_INFO to detect synthetic frames.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/stack_spoof/validate_all_thread_stacks', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_stack_spoof_detect_unwind', 'Detect frame pointer desynchronization and unwind anomalies.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/stack_spoof/detect_unwind_anomalies', {}), null, 2) }] };
  });
  server.tool('x64dbg_stack_spoof_find_forged_returns', 'Identify forged return addresses landing on non-CALL boundaries.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/stack_spoof/find_forged_return_addresses', {}), null, 2) }] };
  });

  // Phantom DLL
  server.tool('x64dbg_phantom_dll_scan', 'Detect Phantom DLL / unlinked MEM_IMAGE regions mapped via SEC_IMAGE_NO_EXECUTE.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/phantom_dll/scan_unmapped_image_regions', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_phantom_dll_compare_ldr', 'Compare MEM_IMAGE regions against PEB.Ldr module list to detect unlinked modules.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/phantom_dll/compare_against_ldr_list', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_phantom_dll_detect_sec_image', 'Detect Transacted Hollowing and Ghosting SEC_IMAGE_NO_EXECUTE techniques.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/phantom_dll/detect_sec_image_no_execute', {}), null, 2) }] };
  });

  // Heap Spray
  server.tool('x64dbg_heap_spray_detect', 'Detect heap spraying and NOP sleds in process heap blocks.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/heap_spray/scan_all_heaps', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_heap_spray_detect_patterns', 'Scan heap blocks for repeating DWORD patterns and TypedArray sprays.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/heap_spray/detect_spray_patterns', {}), null, 2) }] };
  });
  server.tool('x64dbg_heap_spray_calc_density', 'Calculate shellcode density and instruction entropy in heap.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/heap_spray/calculate_shellcode_density', {}), null, 2) }] };
  });

  // Anti-Disassembly
  server.tool('x64dbg_anti_disasm_detect', 'Detect overlapping instructions and jump-into-middle tricks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/anti_disasm/detect_overlapping_instructions', {}), null, 2) }] };
  });
  server.tool('x64dbg_anti_disasm_find_prefixes', 'Find junk byte prefixes (0x66, 0x67, REX) and LOCK misuse.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/anti_disasm/find_junk_prefixes', {}), null, 2) }] };
  });
  server.tool('x64dbg_anti_disasm_compare_linear', 'Compare linear sweep vs recursive descent disassembly output.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/anti_disasm/compare_linear_vs_recursive', {}), null, 2) }] };
  });

  // Timing Side-channels
  server.tool('x64dbg_timing_sidechannel_find_rdtsc', 'Scan code for RDTSC / RDTSCP / RDPMC instructions.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/timing_side/find_rdtsc_checks', {}), null, 2) }] };
  });
  server.tool('x64dbg_timing_sidechannel_profile_pmc', 'Profile performance monitoring counter (PMC) usage.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/timing_side/profile_pmc_usage', {}), null, 2) }] };
  });
  server.tool('x64dbg_timing_sidechannel_detect_cache', 'Detect Flush+Reload and Prime+Probe cache timing side-channels.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/timing_side/detect_cache_timing_checks', {}), null, 2) }] };
  });

  // Exception-Oriented Programming (EOP)
  server.tool('x64dbg_eop_trace_control_flow', 'Trace intentional hardware exceptions handled by VEH to reconstruct CFG.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/eop/trace_exception_control_flow', {}), null, 2) }] };
  });
  server.tool('x64dbg_eop_detect_intentional_faults', 'Detect intentional divide-by-zero, #GP, and #DB trap instructions.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/eop/detect_intentional_exceptions', {}), null, 2) }] };
  });
  server.tool('x64dbg_eop_map_veh_graph', 'Map VEH exception dispatcher graph and synthesize unconditional edges.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/eop/map_veh_dispatch_graph', {}), null, 2) }] };
  });
}
