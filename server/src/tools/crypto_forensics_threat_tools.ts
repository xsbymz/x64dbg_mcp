import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoForensicsThreatTools(server: McpServer) {
  // Certificate Store
  server.tool('x64dbg_cert_store_audit', 'Inspect Windows Certificate Stores (MY, ROOT, CA, Trust, Disallowed).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cert_store/enumerate_all_stores', {}), null, 2) }] };
  });
  server.tool('x64dbg_cert_store_detect_rogue_cas', 'Detect rogue self-signed Root CA certificates enabling TLS decryption.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cert_store/detect_rogue_root_cas', {}), null, 2) }] };
  });
  server.tool('x64dbg_cert_store_validate_trusted_list', 'Validate store certificates against Microsoft authroot.stl.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cert_store/validate_against_microsoft_trusted_list', {}), null, 2) }] };
  });

  // BCrypt / CNG Providers
  server.tool('x64dbg_bcrypt_audit_providers', 'Enumerate registered CNG cryptographic primitive providers.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/bcrypt/enumerate_providers', {}), null, 2) }] };
  });
  server.tool('x64dbg_bcrypt_validate_signatures', 'Verify Authenticode signatures of CNG cryptography providers.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/bcrypt/validate_provider_signatures', {}), null, 2) }] };
  });
  server.tool('x64dbg_bcrypt_detect_rogue_providers', 'Detect rogue CNG provider registrations intercepting BCryptEncrypt.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/bcrypt/detect_rogue_providers', {}), null, 2) }] };
  });

  // RNG Entropy Tester
  server.tool('x64dbg_rng_test_entropy', 'Collect system PRNG output samples.', { sample_size: z.number().optional() }, async ({ sample_size }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rng/collect_samples', { sample_size: sample_size ?? 4096 }), null, 2) }] };
  });
  server.tool('x64dbg_rng_run_nist_tests', 'Run NIST SP 800-22 statistical entropy tests on PRNG samples.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rng/run_nist_tests', {}), null, 2) }] };
  });
  server.tool('x64dbg_rng_detect_weak_prng', 'Detect weak/predictable PRNG algorithms (time-seeded, static constants).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rng/detect_weak_prng', {}), null, 2) }] };
  });

  // SSL Pinning Bypass
  server.tool('x64dbg_ssl_pinning_detect_hashes', 'Detect hardcoded certificate pinning hashes (SPKI SHA-256).', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ssl_pinning/detect_pinned_hashes', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_ssl_pinning_locate_callbacks', 'Locate TLS certificate validation callbacks in memory.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ssl_pinning/locate_validation_callbacks', {}), null, 2) }] };
  });
  server.tool('x64dbg_ssl_pinning_generate_bypass', 'Generate automated bypass hook strategies for TLS pinning.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ssl_pinning/generate_bypass_strategy', {}), null, 2) }] };
  });

  // LOLBin Arguments
  server.tool('x64dbg_lolbin_extract_command_line', 'Extract command line arguments from PEB/WMI/ETW.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/lolbin/extract_command_line', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_lolbin_detect_patterns', 'Match command line against LOLBin execution patterns.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/lolbin/detect_known_patterns', {}), null, 2) }] };
  });
  server.tool('x64dbg_lolbin_decode_arguments', 'Decode obfuscated and base64 encoded LOLBin arguments.', { command_line: z.string().describe('Command line') }, async ({ command_line }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/lolbin/decode_encoded_arguments', { command_line }), null, 2) }] };
  });

  // Process Ancestry
  server.tool('x64dbg_proc_ancestry_build_tree', 'Build full process ancestry parent-child tree.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/proc_ancestry/build_full_tree', {}), null, 2) }] };
  });
  server.tool('x64dbg_proc_ancestry_detect_anomalies', 'Detect anomalous parent-child relationships (Word spawning cmd).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/proc_ancestry/detect_anomalous_relationships', {}), null, 2) }] };
  });
  server.tool('x64dbg_proc_ancestry_correlate_events', 'Correlate process tree with Event ID 4688 to detect PPID spoofing.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/proc_ancestry/correlate_with_event_log', {}), null, 2) }] };
  });

  // Lateral Movement
  server.tool('x64dbg_lateral_movement_psexec', 'Detect PsExec service and pipe indicators.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/lateral_move/detect_psexec_indicators', {}), null, 2) }] };
  });
  server.tool('x64dbg_lateral_movement_winrm', 'Detect WinRM PowerShell remoting activity.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/lateral_move/detect_winrm_activity', {}), null, 2) }] };
  });
  server.tool('x64dbg_lateral_movement_wmi', 'Detect WMI remote process creation execution.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/lateral_move/detect_wmi_execution', {}), null, 2) }] };
  });

  // LOLDrivers / BYOVD
  server.tool('x64dbg_loldrivers_scan', 'Scan loaded drivers for BYOVD attack techniques.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/loldriver/scan_loaded_drivers', {}), null, 2) }] };
  });
  server.tool('x64dbg_loldrivers_match_vulnerable', 'Match loaded drivers against loldrivers.io database.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/loldriver/match_against_known_vulnerable', {}), null, 2) }] };
  });
  server.tool('x64dbg_loldrivers_assess_risk', 'Assess BYOVD risk and WDAC driver blocklist enforcement.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/loldriver/assess_byovd_risk', {}), null, 2) }] };
  });

  // Registry Hive (REGF)
  server.tool('x64dbg_reg_hive_parse', 'Parse raw offline registry hive headers and bins.', { hive_path: z.string().optional() }, async ({ hive_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/reg_hive/parse_hive_file', { hive_path: hive_path ?? 'C:\\Windows\\System32\\config\\SAM' }), null, 2) }] };
  });
  server.tool('x64dbg_reg_hive_extract_sam', 'Extract NTLM hashes offline from SAM and SYSTEM hives.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/reg_hive/extract_sam_hashes', {}), null, 2) }] };
  });
  server.tool('x64dbg_reg_hive_read_lsa_secrets', 'Extract offline LSA secrets and machine account credentials.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/reg_hive/read_lsa_secrets_offline', {}), null, 2) }] };
  });

  // Memory Artifact Correlator
  server.tool('x64dbg_mem_correlate_iocs', 'Scan memory for IPv4, URL, crypto key, and wallet IOCs.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_correlate/scan_ioc_patterns', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_mem_correlate_embedded_pes', 'Scan memory blocks for unmapped embedded PE payload binaries.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_correlate/find_embedded_pes', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_mem_correlate_network', 'Correlate discovered memory strings with active socket connections.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_correlate/extract_network_iocs', {}), null, 2) }] };
  });

  // PowerShell ScriptBlock
  server.tool('x64dbg_ps_scriptblock_extract', 'Extract cached PowerShell ScriptBlock text from CLR heap.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ps_scriptblock/extract_from_memory', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_ps_scriptblock_decode', 'Decode obfuscated PowerShell script blocks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ps_scriptblock/decode_obfuscated_blocks', {}), null, 2) }] };
  });
  server.tool('x64dbg_ps_scriptblock_detect_amsi_bypass', 'Detect in-memory AMSI patching and reflection bypasses.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ps_scriptblock/detect_amsi_bypass_patterns', {}), null, 2) }] };
  });

  // Supply Chain Scanner
  server.tool('x64dbg_supply_chain_audit_binary', 'Audit binary build artifacts for supply chain trojanization.', { binary_path: z.string().describe('Binary path') }, async ({ binary_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/supply_chain/audit_build_artifacts', { binary_path }), null, 2) }] };
  });
  server.tool('x64dbg_supply_chain_detect_trojanized', 'Detect historic supply chain indicators (SUNBURST, 3CX, XZ).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/supply_chain/detect_trojanized_indicators', {}), null, 2) }] };
  });
  server.tool('x64dbg_supply_chain_verify_vendor', 'Validate digital certificate vendor organization chain.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/supply_chain/verify_vendor_chain', {}), null, 2) }] };
  });
}
