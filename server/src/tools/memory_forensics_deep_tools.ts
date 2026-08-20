import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryForensicsDeepTools(server: McpServer) {
  // JIT Spray
  server.tool('x64dbg_jit_spray_scan', 'Detect JIT spray attacks in JIT engine memory regions.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/jit_spray/scan_jit_regions', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_jit_spray_detect_embedded', 'Detect embedded shellcode sequences inside JIT arithmetic immediates.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/jit_spray/detect_embedded_shellcode', {}), null, 2) }] };
  });
  server.tool('x64dbg_jit_spray_analyze_immediates', 'Analyze immediate byte patterns for constant blinding evaluation.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/jit_spray/analyze_immediate_byte_patterns', {}), null, 2) }] };
  });

  // Use-After-Free (UAF)
  server.tool('x64dbg_uaf_tag_allocations', 'Tag heap allocations with canary headers and poison freed blocks.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/uaf/tag_allocations', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_uaf_detect_stale_access', 'Detect stale pointer read/write access to quarantined freed heap chunks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/uaf/detect_stale_access', {}), null, 2) }] };
  });
  server.tool('x64dbg_uaf_analyze_heap_entropy', 'Analyze LFH heap ASLR randomization entropy.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/uaf/analyze_heap_entropy', {}), null, 2) }] };
  });

  // Memory Forensics Timeline
  server.tool('x64dbg_mem_timeline_reconstruct', 'Reconstruct chronological memory allocation order.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_timeline/reconstruct_allocation_order', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_mem_timeline_correlate_threads', 'Correlate memory allocations with thread creation events.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_timeline/correlate_with_thread_creation', {}), null, 2) }] };
  });
  server.tool('x64dbg_mem_timeline_export_sequence', 'Export chronological memory event sequence as JSON.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_timeline/export_forensic_sequence', {}), null, 2) }] };
  });

  // PEB LDR Integrity
  server.tool('x64dbg_peb_ldr_check_integrity', 'Cross-check all three PEB.Ldr module lists to detect partial unlinking.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/peb_ldr/check_all_three_lists', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_peb_ldr_detect_partial_unlink', 'Detect partial unlinking disparities among the three PEB module lists.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/peb_ldr/detect_partial_unlink', {}), null, 2) }] };
  });
  server.tool('x64dbg_peb_ldr_cross_validate', 'Cross-validate PEB.Ldr vs Toolhelp32 vs PSAPI vs kernel module list.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/peb_ldr/cross_validate_module_lists', {}), null, 2) }] };
  });

  // Code Signing Memory Validator
  server.tool('x64dbg_code_sig_validate_memory', 'Verify in-memory .text section SHA256 against on-disk Authenticode signature.', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/code_sig/rehash_memory_sections', { module_name: module_name ?? 'ntdll.dll' }), null, 2) }] };
  });
  server.tool('x64dbg_code_sig_compare_authenticode', 'Compare memory hash against Authenticode PKCS#7 signed catalog.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/code_sig/compare_against_authenticode', {}), null, 2) }] };
  });
  server.tool('x64dbg_code_sig_detect_tampering', 'Detect signed binary code section tampering and inline hooks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/code_sig/detect_signed_binary_tampering', {}), null, 2) }] };
  });
}
