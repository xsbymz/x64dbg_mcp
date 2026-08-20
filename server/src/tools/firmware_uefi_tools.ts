import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFirmwareUefiTools(server: McpServer) {
  // UEFI Runtime Services
  server.tool(
    'x64dbg_uefi_dump_runtime_table',
    'Dump the EFI Runtime Services function pointer table (GetVariable, SetVariable, ResetSystem, UpdateCapsule). Identifies bootkit hooks (FinFisher, Lojax, MoonBounce).',
    {},
    async () => {
      const result = await httpClient.post('/api/uefi/dump_runtime_table', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_uefi_validate_service_pointers',
    'Validate all EFI Runtime Service pointers against loaded kernel modules (ntoskrnl.exe, hal.dll).',
    {},
    async () => {
      const result = await httpClient.post('/api/uefi/validate_service_pointers', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_uefi_detect_bootkit_hooks',
    'Detect active UEFI bootkit hooks and check Secure Boot firmware state.',
    {},
    async () => {
      const result = await httpClient.post('/api/uefi/detect_bootkit_hooks', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  // UEFI NVRAM
  server.tool(
    'x64dbg_uefi_nvram_enumerate_variables',
    'Enumerate critical UEFI NVRAM variables (SecureBoot, SetupMode, AuditMode, BootOrder, PK, KEK, db, dbx).',
    {},
    async () => {
      const result = await httpClient.post('/api/uefi_nvram/enumerate_variables', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_uefi_nvram_read_variable',
    'Read raw binary/hex data of a specific UEFI NVRAM variable by name and vendor GUID.',
    {
      name: z.string().describe('Variable name (e.g. "SecureBoot", "BootOrder")'),
      guid: z.string().optional().describe('Vendor GUID (default: EFI Global Variable GUID)'),
    },
    async ({ name, guid }) => {
      const result = await httpClient.post('/api/uefi_nvram/read_variable', { name, guid });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_uefi_nvram_check_secureboot_state',
    'Evaluate Secure Boot activation, SetupMode, AuditMode, and DeployedMode states for bypass vulnerabilities.',
    {},
    async () => {
      const result = await httpClient.post('/api/uefi_nvram/check_secureboot_state', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  // TPM PCR Banks
  server.tool(
    'x64dbg_tpm_read_pcr_banks',
    'Read TPM 2.0 PCR (Platform Configuration Register) banks and assess BitLocker sealing configuration.',
    {},
    async () => {
      const result = await httpClient.post('/api/tpm/read_pcr_banks', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_tpm_get_ek_certificate',
    'Extract and verify the TPM Endorsement Key (EK) certificate from TPM NVRAM.',
    {},
    async () => {
      const result = await httpClient.post('/api/tpm/get_ek_certificate', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_tpm_analyze_measurement_log',
    'Parse TCG EFI Measured Boot binary log files (C:\\Windows\\Logs\\MeasuredBoot).',
    {},
    async () => {
      const result = await httpClient.post('/api/tpm/analyze_measurement_log', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  // ACPI Tables
  server.tool(
    'x64dbg_acpi_enumerate_tables',
    'Enumerate ACPI system firmware tables (DSDT, SSDT, MADT, DMAR, MCFG, FACP).',
    {},
    async () => {
      const result = await httpClient.post('/api/acpi/enumerate_tables', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_acpi_parse_dsdt',
    'Parse ACPI DSDT (Differentiated System Description Table) header, AML bytecode, and checksum.',
    {},
    async () => {
      const result = await httpClient.post('/api/acpi/parse_dsdt', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_acpi_validate_dmar_entries',
    'Validate DMAR (DMA Remapping) IOMMU tables to assess hardware DMA attack surface.',
    {},
    async () => {
      const result = await httpClient.post('/api/acpi/validate_dmar_entries', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  // SPI Flash
  server.tool(
    'x64dbg_spi_read_descriptor_map',
    'Read Intel SPI Flash Descriptor layout, region permissions, and master access rights.',
    {},
    async () => {
      const result = await httpClient.post('/api/spi/read_descriptor_map', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_spi_get_region_access_rights',
    'Inspect SPI Protected Range Registers (PR0-PR4) and SMM_BWP / BIOS_CNTL lock states.',
    {},
    async () => {
      const result = await httpClient.post('/api/spi/get_region_access_rights', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_spi_detect_region_anomalies',
    'Detect SPI flash BIOS write protection tampering and firmware implant anomalies.',
    {},
    async () => {
      const result = await httpClient.post('/api/spi/detect_region_anomalies', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
