import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeExportForwarderChaserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_export_forwarder_chaser',
    'Chase multi-hop PE export forwarders (e.g. api-ms-win-crt-runtime-l1-1-0.dll -> ucrtbase.dll!terminate) and validate final target function address.',
    {
      action: z.enum(['chase_forwarder', 'list_all_module_forwarders', 'detect_broken_forwarders']).describe('Forwarder chaser action'),
      module_name: z.string().describe('Module name (e.g. kernel32.dll)'),
      function_name: z.string().optional().describe('Exported function name to chase'),
    },
    async ({ action, module_name, function_name }) => {
      let data: unknown;
      switch (action) {
        case 'chase_forwarder':
          data = await httpClient.post('/api/forwarder_chaser/chase', { module_name, function_name });
          break;
        case 'list_all_module_forwarders':
          data = await httpClient.post('/api/forwarder_chaser/module', { module_name });
          break;
        case 'detect_broken_forwarders':
          data = await httpClient.post('/api/forwarder_chaser/broken', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
