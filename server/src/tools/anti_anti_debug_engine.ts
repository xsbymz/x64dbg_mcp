import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAntiAntiDebugEngineTools(server: McpServer) {
  server.tool(
    'x64dbg_anti_anti_debug_engine',
    'Automate cloaking of x64dbg (clears BeingDebugged, NtGlobalFlag, ProcessDebugPort, ProcessDebugObjectHandle, and hooks RDTSC/CPUID).',
    {
      action: z.enum(['enable_full_stealth', 'disable_stealth', 'get_cloaking_status', 'cloak_specific_flag']).describe('Stealth engine action'),
      flag_name: z.string().optional().describe('Flag name (e.g. NtGlobalFlag, BeingDebugged, HeapFlags)'),
    },
    async ({ action, flag_name }) => {
      let data: unknown;
      switch (action) {
        case 'enable_full_stealth':
          data = await httpClient.post('/api/stealth/enable');
          break;
        case 'disable_stealth':
          data = await httpClient.post('/api/stealth/disable');
          break;
        case 'get_cloaking_status':
          data = await httpClient.get('/api/stealth/status');
          break;
        case 'cloak_specific_flag':
          data = await httpClient.post('/api/stealth/cloak_flag', { flag_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
