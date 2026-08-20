import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHypervisorVmcallTrapDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hypervisor_vmcall_trap_detector',
    'Detect VMCALL/VMMCALL hypervisor backdoor traps, synthetic MSR accesses, and hypervisor guest-to-host interface probes.',
    {
      action: z.enum(['scan_vmcall_instructions', 'check_synthetic_msrs', 'detect_hypervisor_backdoors']).describe('VMCALL detector action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'scan_vmcall_instructions':
          data = await httpClient.get('/api/vmcall_trap/scan');
          break;
        case 'check_synthetic_msrs':
          data = await httpClient.get('/api/vmcall_trap/msrs');
          break;
        case 'detect_hypervisor_backdoors':
          data = await httpClient.get('/api/vmcall_trap/backdoors');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
