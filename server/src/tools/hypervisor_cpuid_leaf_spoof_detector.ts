import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHypervisorCpuidLeafSpoofDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hypervisor_cpuid_leaf_spoof_detector',
    'Cross-check synthetic hypervisor CPUID leaves (0x40000000 - 0x40000010) against physical MSRs to detect CPUID spoofing & emulation.',
    {
      action: z.enum(['audit_cpuid_leaves', 'detect_spoofed_signatures', 'get_synthetic_features']).describe('CPUID audit action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'audit_cpuid_leaves':
          data = await httpClient.get('/api/cpuid_spoof/audit');
          break;
        case 'detect_spoofed_signatures':
          data = await httpClient.get('/api/cpuid_spoof/signatures');
          break;
        case 'get_synthetic_features':
          data = await httpClient.get('/api/cpuid_spoof/features');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
