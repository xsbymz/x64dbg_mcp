import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerBinaryAnalysisDeepTools(server: McpServer) {
  // Compiler Fingerprinter
  server.tool('x64dbg_compiler_identify_toolchain', 'Identify compiler toolchain (MSVC, GCC, Clang, Rust, Go, Delphi).', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/compiler_fp/identify_toolchain', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_compiler_extract_versions', 'Extract compiler version indicators and Rich Header ProdIDs.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/compiler_fp/extract_version_indicators', {}), null, 2) }] };
  });
  server.tool('x64dbg_compiler_detect_obfuscation', 'Detect stripped Rich Headers and obfuscated compiler trails.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/compiler_fp/detect_obfuscated_compiler_trails', {}), null, 2) }] };
  });

  // PDB GUID Mismatch
  server.tool('x64dbg_pdb_guid_validate_symbols', 'Validate PDB CodeView GUID against Microsoft Symbol Server.', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/pdb_guid/extract_debug_info', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_pdb_guid_compare_server', 'Query Microsoft Symbol Server to verify system binary authenticity.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/pdb_guid/compare_with_symbol_server', {}), null, 2) }] };
  });
  server.tool('x64dbg_pdb_guid_check_malware', 'Check PDB GUIDs and paths against known malware builder signatures.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/pdb_guid/check_known_malware_guids', {}), null, 2) }] };
  });

  // CFI / Control Flow Guard
  server.tool('x64dbg_cfi_dump_cfg_bitmap', 'Inspect Control Flow Guard (CFG) bitmaps and valid call targets.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cfi/dump_cfg_bitmap', {}), null, 2) }] };
  });
  server.tool('x64dbg_cfi_find_bypass_gadgets', 'Find CFG bypass gadget candidates in valid target tables.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cfi/find_cfg_bypass_gadgets', {}), null, 2) }] };
  });
  server.tool('x64dbg_cfi_analyze_valid_targets', 'Analyze valid indirect call target RVAs in LoadConfig.', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cfi/analyze_valid_call_targets', { module_name: module_name ?? '' }), null, 2) }] };
  });

  // Binary Diffing Vuln Locator
  server.tool('x64dbg_bindiff_compare_patch', 'Compare original vs patched binaries to locate security fixes.', { original: z.string().describe('Path to pre-patch binary'), patched: z.string().describe('Path to post-patch binary') }, async ({ original, patched }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/bindiff/compare_versions', { original, patched }), null, 2) }] };
  });
  server.tool('x64dbg_bindiff_locate_security_patches', 'Identify bounds check, overflow check, and null validation patch insertions.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/bindiff/locate_security_patches', {}), null, 2) }] };
  });
  server.tool('x64dbg_bindiff_assess_nday_surface', 'Assess N-day 1-day exploit feasibility from binary patch diffs.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/bindiff/assess_nday_exploit_surface', {}), null, 2) }] };
  });

  // Exception Handler ROP Gadgets
  server.tool('x64dbg_eh_rop_find_gadgets', 'Extract CFG-authenticated ROP gadgets from PE exception handlers.', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/eh_rop/enumerate_handler_addresses', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_eh_rop_extract_gadgets', 'Extract clean unwind epilogue and register-setting gadgets from filters.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/eh_rop/extract_gadgets_from_handlers', {}), null, 2) }] };
  });
  server.tool('x64dbg_eh_rop_build_authenticated_set', 'Build authenticated ROP gadget set passing CFG verification.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/eh_rop/build_authenticated_gadget_set', {}), null, 2) }] };
  });
}
