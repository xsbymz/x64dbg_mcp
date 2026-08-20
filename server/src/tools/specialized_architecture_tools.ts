import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSpecializedArchitectureTools(server: McpServer) {
  // VMCS Field & Exit Reason Decoder
  server.tool('x64dbg_vmcs_decode_field_encoding', 'Decode Intel VMCS field 32-bit encoding (Type, Width, Index, Full/High access).', { encoding: z.string().describe('Encoding hex e.g. 0x00004800') }, async ({ encoding }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vmcs_decoder/decode_field_encoding', { encoding }), null, 2) }] };
  });
  server.tool('x64dbg_vmcs_decode_exit_reason', 'Decode basic VM-Exit reason numerical codes and qualification semantics.', { exit_reason: z.number().describe('Basic exit reason code') }, async ({ exit_reason }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vmcs_decoder/decode_exit_reason', { exit_reason }), null, 2) }] };
  });

  // Paging Walker & PCID Explorer
  server.tool('x64dbg_paging_walk_virtual_address', 'Calculate 4-level and 5-level (LA57) page table indices for a 64-bit virtual address.', { virtual_address: z.string().describe('Virtual address hex') }, async ({ virtual_address }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/paging/walk_virtual_address', { virtual_address }), null, 2) }] };
  });
  server.tool('x64dbg_paging_inspect_pcid_layout', 'Inspect CR3 PCID (Process-Context Identifier) layout and KPTI isolation design.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/paging/inspect_pcid_layout', {}), null, 2) }] };
  });

  // LoadConfig Deep & Security Mitigations
  server.tool('x64dbg_load_config_parse_mitigations', 'Parse extended PE LoadConfig security directory (CFG, XFG, CastGuard, CET Shadow Stack).', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/load_config/parse_security_mitigations', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_load_config_audit_cet_shadow_stack', 'Audit hardware CET Shadow Stack and GuardEHContinuationTable protections.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/load_config/audit_cet_shadow_stack', {}), null, 2) }] };
  });

  // SMT-LIB2 Solver Bridge
  server.tool('x64dbg_smt_solver_format_bv_formula', 'Synthesize SMT-LIB v2.6 QF_BV formula for bitvector constraint solving.', { target_register: z.string().optional(), expression: z.string().optional() }, async ({ target_register, expression }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/smt_solver/format_bitvector_formula', { target_register: target_register ?? 'rax', expression: expression ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_smt_solver_generate_crackme_template', 'Generate SMT-LIB2 crackme keygen constraint satisfaction template.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/smt_solver/generate_crackme_key_constraints', {}), null, 2) }] };
  });
}
