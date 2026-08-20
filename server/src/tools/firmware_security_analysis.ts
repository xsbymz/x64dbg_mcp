import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFirmwareSecurityAnalysisTools(server: McpServer) {
  server.tool('x64dbg_fw_analyze_uefi_runtime', 'Analyze UEFI Runtime Services: GetVariable, SetVariable, QueryVariableInfo, UpdateCapsule.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/analyze_uefi_runtime', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_detect_uefi_bootkit', 'Detect UEFI bootkits via firmware volume integrity checks and Boot Services abuse.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/detect_uefi_bootkit', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_read_spi_flash', 'Read SPI flash regions: descriptor, BIOS, ME, GbE, PDR via PCI configuration space.', { region: z.string().optional() }, async ({ region }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/read_spi_flash', { region: region ?? 'bios' }), null, 2) }] };
  });
  server.tool('x64dbg_fw_analyze_smm', 'Analyze System Management Mode (SMM) handlers: SMI handlers, SMRAM, SMM privilege escalation.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/analyze_smm', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_detect_smm_abuse', 'Detect SMM handler abuse: SMI command injection, SMRAM corruption, SMM privilege escalation.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/detect_smm_abuse', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_analyze_intel_me', 'Analyze Intel Management Engine (ME) firmware: ME region, HAP bit, ME firmware version.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/analyze_intel_me', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_analyze_amd_psp', 'Analyze AMD Platform Security Processor (PSP) firmware: PSP directory, bootloaders, vulnerabilities.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/analyze_amd_psp', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_parse_acpi_tables', 'Parse ACPI tables: DSDT, SSDT, MADT, MCFG, SRAT for firmware vulnerabilities.', { table_signature: z.string().optional() }, async ({ table_signature }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/parse_acpi_tables', { table_signature: table_signature ?? 'DSDT' }), null, 2) }] };
  });
  server.tool('x64dbg_fw_detect_acpi_bios', 'Detect ACPI BIOS vulnerabilities: _OSI abuse, SMM callbacks, AML bytecode injection.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/detect_acpi_bios_vulnerabilities', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_analyze_nvram_variables', 'Analyze UEFI NVRAM variables: BootOrder, Boot####, secure boot keys, backdoor variables.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/analyze_nvram_variables', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_detect_persistent_backdoor', 'Detect persistent firmware backdoors: bootkit persistence, boot order hijack, option ROM malware.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/detect_persistent_backdoor', {}), null, 2) }] };
  });
  server.tool('x64dbg_fw_verify_boot_chain', 'Verify UEFI Secure Boot chain: db/KEK/db integrity, signature validation, boot manager integrity.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/firmware/verify_boot_chain', {}), null, 2) }] };
  });
}
