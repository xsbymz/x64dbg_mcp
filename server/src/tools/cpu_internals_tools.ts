import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { httpClient } from '../http_client.js';

export function registerCpuInternalsTools(server: McpServer) {
  // IDT Hooks
  server.tool('x64dbg_idt_dump_table', 'Dump Interrupt Descriptor Table (IDT) gates with handler VAs.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/idt/dump_table', {}), null, 2) }] };
  });
  server.tool('x64dbg_idt_validate_gate_handlers', 'Validate IDT gate handlers against loaded kernel modules.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/idt/validate_gate_handlers', {}), null, 2) }] };
  });
  server.tool('x64dbg_idt_detect_hooked_vectors', 'Detect hooked interrupt vectors (#DB, #BP, #PF, NMI).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/idt/detect_hooked_vectors', {}), null, 2) }] };
  });

  // GDT Segments
  server.tool('x64dbg_gdt_dump_table', 'Dump Global Descriptor Table (GDT) segment descriptors.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/gdt/dump_table', {}), null, 2) }] };
  });
  server.tool('x64dbg_gdt_find_call_gates', 'Scan GDT for Call Gates (type 0x0C) and Task Gates.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/gdt/find_call_gates', {}), null, 2) }] };
  });
  server.tool('x64dbg_gdt_detect_priv_esc', 'Detect GDT descriptors modified for privilege escalation.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/gdt/detect_privilege_escalation_descriptors', {}), null, 2) }] };
  });

  // MSR Auditor
  server.tool('x64dbg_msr_read_critical_msrs', 'Read critical security MSRs (LSTAR, EFER, SPEC_CTRL, ARCH_CAPS).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/msr/read_critical_msrs', {}), null, 2) }] };
  });
  server.tool('x64dbg_msr_detect_lstar_hook', 'Check if IA32_LSTAR points outside ntoskrnl KiSystemCall64.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/msr/detect_lstar_hook', {}), null, 2) }] };
  });
  server.tool('x64dbg_msr_audit_mitigations', 'Audit hardware speculative execution mitigation MSRs.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/msr/audit_mitigation_msrs', {}), null, 2) }] };
  });

  // CPU Vulnerability Scanner
  server.tool('x64dbg_cpu_vuln_read_cpuid_leaves', 'Read CPUID vulnerability and mitigation leaves.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cpu_vuln/read_cpuid_vulnerability_leaves', {}), null, 2) }] };
  });
  server.tool('x64dbg_cpu_vuln_check_arch_caps', 'Read IA32_ARCH_CAPABILITIES MSR hardware mitigation flags.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cpu_vuln/check_arch_capabilities_msr', {}), null, 2) }] };
  });
  server.tool('x64dbg_cpu_vuln_assess_mitigations', 'Assess active OS and hardware exploit mitigations (KPTI, IBRS).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cpu_vuln/assess_exploit_mitigations', {}), null, 2) }] };
  });

  // Control Registers (CR0/CR4)
  server.tool('x64dbg_cr_regs_read_all', 'Inspect Control Registers CR0 (WP bit), CR4 (SMEP, SMAP, CET).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cr_regs/read_all', {}), null, 2) }] };
  });
  server.tool('x64dbg_cr_regs_check_smep_smap', 'Audit SMEP/SMAP exploit mitigation status.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cr_regs/check_smep_smap', {}), null, 2) }] };
  });
  server.tool('x64dbg_cr_regs_detect_cleared_wp', 'Detect cleared CR0.WP (Write Protect) bit in kernel mode.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cr_regs/detect_cleared_wp_bit', {}), null, 2) }] };
  });

  // Microcode & SGX & PAT/MTRR
  server.tool('x64dbg_microcode_read_version', 'Read CPU microcode update revision.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/microcode/read_version', {}), null, 2) }] };
  });
  server.tool('x64dbg_microcode_check_patch_level', 'Check microcode vulnerability patch level against Intel/AMD database.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/microcode/check_patch_level', {}), null, 2) }] };
  });
  server.tool('x64dbg_microcode_assess_exposure', 'Assess system vulnerability exposure due to outdated microcode.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/microcode/assess_vulnerability_exposure', {}), null, 2) }] };
  });

  server.tool('x64dbg_sgx_detect_enclaves', 'Detect Intel SGX support and Enclave Page Cache layout.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sgx/detect_enclaves', {}), null, 2) }] };
  });
  server.tool('x64dbg_sgx_read_epc_layout', 'Read SGX Enclave Page Cache (EPC) structures (SECS, TCS, REG).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sgx/read_epc_layout', {}), null, 2) }] };
  });
  server.tool('x64dbg_sgx_analyze_sigstruct', 'Analyze SGX SIGSTRUCT headers and MRENCLAVE identity.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sgx/analyze_sigstruct', {}), null, 2) }] };
  });

  server.tool('x64dbg_mtrr_read_all', 'Inspect PAT and MTRR memory type range registers.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mtrr/read_all', {}), null, 2) }] };
  });
  server.tool('x64dbg_mtrr_detect_suspicious_uc', 'Detect suspicious uncacheable (UC) memory regions hiding rootkits.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mtrr/detect_suspicious_uc_regions', {}), null, 2) }] };
  });
  server.tool('x64dbg_pat_read_entry_table', 'Read Page Attribute Table (PAT) MSR entry mappings.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/pat/read_entry_table', {}), null, 2) }] };
  });
}
