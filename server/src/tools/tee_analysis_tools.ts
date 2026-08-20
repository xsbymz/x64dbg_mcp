import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTeeAnalysisTools(server: McpServer) {
  server.tool('x64dbg_tee_detect_sev_snp', 'Detect AMD SEV-SNP (Secure Encrypted Virtualization with Secure Nested Paging) support and status.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/detect_sev_snp', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_detect_tdx', 'Detect Intel TDX (Trust Domain Extensions) support and active TDX domains.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/detect_tdx', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_detect_arm_cca', 'Detect ARM Confidential Compute Architecture (CCA) Realm support.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/detect_arm_cca', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_analyze_vc_handler', 'Analyze AMD SEV-SNP #VC (VMM Communication Exception) handler for injection vulnerabilities (WeSee attack surface).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/analyze_vc_handler', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_detect_interrupt_injection', 'Detect malicious interrupt injection vectors in SEV-SNP/TDX (int 0x80, #VC, NMI).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/detect_interrupt_injection', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_audit_ghcb_protocol', 'Audit AMD SEV-SNP GHCB (Guest Hypervisor Communication Block) protocol usage for Iago attacks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/audit_ghcb_protocol', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_detect_heckler_vectors', 'Detect HECKLER-style interrupt injection attack surfaces (CVE-2024-25743, CVE-2024-25744).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/detect_heckler_vectors', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_analyze_sgx_enclave', 'Analyze Intel SGX enclave security: EPCM, SECS, TCS, MRENCLAVE identity.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/analyze_sgx_enclave', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_detect_sgx_enclave_abuse', 'Detect SGX enclave abuse: malicious ENCLU, EENTER misuse, and side-channel exposure.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/detect_sgx_enclave_abuse', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_audit_tdx_io', 'Audit Intel TDX I/O and SEAM (Software Guard Extensions) module integrity.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/audit_tdx_io', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_map_cvm_attack_surface', 'Map complete attack surface of confidential VMs: hypervisor interfaces, interrupt handlers, MMIO.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/map_cvm_attack_surface', {}), null, 2) }] };
  });
  server.tool('x64dbg_tee_detect_memory_encryption_bypass', 'Detect potential memory encryption bypass vectors in SEV-SNP/TDX implementations.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/tee/detect_memory_encryption_bypass', {}), null, 2) }] };
  });
}
