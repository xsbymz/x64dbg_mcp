import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDeepBinaryVirtualizationTools(server: McpServer) {
  // VMX Capabilities
  server.tool('x64dbg_vmx_cap_audit_msrs', 'Audit Intel VMX hardware virtualization MSRs (IA32_VMX_BASIC, PINBASED, PROCBASED, EPT_VPID).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vmx_cap/audit_msrs', {}), null, 2) }] };
  });
  server.tool('x64dbg_vmx_cap_evaluate_nested', 'Evaluate hypervisor nested virtualization capabilities and Shadow VMCS support.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vmx_cap/evaluate_nested_virt', {}), null, 2) }] };
  });

  // EPT Page Walker
  server.tool('x64dbg_ept_walk_simulate', 'Simulate Extended Page Table (EPT) 4-level paging walk from GPA to HPA.', { guest_physical_address: z.string().describe('Guest physical address hex') }, async ({ guest_physical_address }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ept_walk/simulate_translation', { guest_physical_address }), null, 2) }] };
  });
  server.tool('x64dbg_ept_walk_detect_hooks', 'Detect split EPT permissions and shadow page rootkit execution hooks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ept_walk/detect_hidden_hooks', {}), null, 2) }] };
  });

  // Intel Processor Trace (PT)
  server.tool('x64dbg_intel_pt_decode_stream', 'Decode raw Intel PT hardware packet stream (PSB, TNT, TIP, FUP, PIP).', { raw_packets_hex: z.string().describe('Raw packet bytes hex') }, async ({ raw_packets_hex }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/intel_pt/decode_packet_stream', { raw_packets_hex }), null, 2) }] };
  });
  server.tool('x64dbg_intel_pt_reconstruct_cf', 'Reconstruct non-intrusive control flow trace from Intel PT TNT and TIP packets.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/intel_pt/reconstruct_control_flow', {}), null, 2) }] };
  });

  // Authenticode Leaf Parser
  server.tool('x64dbg_authenticode_parse_leaf', 'Parse Authenticode PKCS#7 signedData structures and X.509 leaf certificate details.', { file_path: z.string().describe('PE binary file path') }, async ({ file_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/authenticode/parse_leaf_cert', { file_path }), null, 2) }] };
  });
  server.tool('x64dbg_authenticode_validate_timestamp', 'Validate RFC 3161 timestamp countersignatures on Authenticode signatures.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/authenticode/validate_timestamp_countersignature', {}), null, 2) }] };
  });

  // Catalog Database Lookup
  server.tool('x64dbg_catalog_db_query_hash', 'Query Windows Security Catalog (CatRoot) database for detached Authenticode signatures.', { file_hash_sha256: z.string().describe('SHA256 file hash') }, async ({ file_hash_sha256 }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/catalog_db/query_by_hash', { file_hash_sha256 }), null, 2) }] };
  });
  server.tool('x64dbg_catalog_db_enumerate_cats', 'Enumerate system security catalog (.cat) files in CatRoot directory.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/catalog_db/enumerate_system_catalogs', {}), null, 2) }] };
  });

  // Security Descriptor DACL Evaluator
  server.tool('x64dbg_sd_eval_access_mask', 'Evaluate NT Security Descriptor DACL ACEs and integrity labels against access masks.', { sddl_string: z.string().optional() }, async ({ sddl_string }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sd_eval/evaluate_access_mask', { sddl_string: sddl_string ?? 'D:(A;;GA;;;WD)' }), null, 2) }] };
  });
  server.tool('x64dbg_sd_eval_parse_sddl', 'Validate and parse SDDL (Security Descriptor Definition Language) strings.', { sddl: z.string().describe('SDDL string') }, async ({ sddl }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sd_eval/parse_sddl', { sddl }), null, 2) }] };
  });

  // DWARF Debug Section Parser
  server.tool('x64dbg_dwarf_parse_sections', 'Parse DWARF 4/5 debug sections (.debug_info, .debug_line, .debug_abbrev) in MinGW/Rust PEs.', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dwarf/parse_sections', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_dwarf_extract_compilation_units', 'Extract DWARF Compilation Unit (CU) headers and DIE attribute structures.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dwarf/extract_compilation_units', {}), null, 2) }] };
  });

  // MSVC RTTI Graph Analyzer
  server.tool('x64dbg_rtti_graph_build_hierarchy', 'Build complete MSVC C++ RTTI class hierarchy graph including multiple/virtual inheritance.', { vtable_address: z.string().describe('Vtable address hex') }, async ({ vtable_address }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rtti_graph/build_hierarchy_graph', { vtable_address }), null, 2) }] };
  });
  server.tool('x64dbg_rtti_graph_demangle_type', 'Demangle MSVC RTTI TypeDescriptor class names.', { mangled_name: z.string().describe('Mangled name') }, async ({ mangled_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rtti_graph/demangle_type_names', { mangled_name }), null, 2) }] };
  });

  // ALPC Endpoint Inspector
  server.tool('x64dbg_alpc_endpoint_enumerate_ports', 'Enumerate system-wide ALPC port endpoints and message attribute configurations.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/alpc_endpoint/enumerate_ports', {}), null, 2) }] };
  });
  server.tool('x64dbg_alpc_endpoint_decode_headers', 'Decode PORT_MESSAGE layout and message attributes.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/alpc_endpoint/decode_message_headers', {}), null, 2) }] };
  });

  // RPC NDR Format Decoder
  server.tool('x64dbg_ndr_format_decode_type', 'Decode RPC Network Data Representation (NDR/NDR64) type format strings.', { format_string_hex: z.string().describe('Format string hex bytes') }, async ({ format_string_hex }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ndr_format/decode_type_format_string', { format_string_hex }), null, 2) }] };
  });
  server.tool('x64dbg_ndr_format_parse_proc', 'Parse RPC NDR procedure format headers and parameter layout.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ndr_format/parse_rpc_proc_format', {}), null, 2) }] };
  });
}
