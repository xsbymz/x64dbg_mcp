import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHypervisorDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hypervisor_detector',
    'Detect and audit hypervisor environments (Hyper-V, KVM, Xen, VMware, VirtualBox) via synthetic MSRs, CPUID leaves (0x40000000+), SLDT/SIDT/SGDT instruction behaviors, and TSC timing variance.',
    {
      action: z.enum(['full_audit', 'cpuid_leaves', 'timing_variance', 'synthetic_msrs']).describe('Hypervisor detection mode'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'full_audit':
          data = await httpClient.get('/api/hypervisor/audit');
          break;
        case 'cpuid_leaves':
          data = await httpClient.get('/api/hypervisor/cpuid');
          break;
        case 'timing_variance':
          data = await httpClient.get('/api/hypervisor/timing');
          break;
        case 'synthetic_msrs':
          data = await httpClient.get('/api/hypervisor/msrs');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
