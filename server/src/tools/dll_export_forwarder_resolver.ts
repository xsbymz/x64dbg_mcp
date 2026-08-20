import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDllExportForwarderResolverTools(server: McpServer) {
  server.tool(
    'x64dbg_dll_export_forwarder_resolver',
    'Recursively resolve DLL export forwarders (e.g. NTDLL.RtlAllocateHeap -> ntdll.dll!RtlAllocateHeap) across nested module dependencies.',
    {
      action: z.enum(['resolve_forwarder', 'scan_module_forwarders', 'trace_forwarder_chain']).describe('Forwarder resolver action'),
      module_name: z.string().optional().describe('Module name (e.g. kernel32.dll)'),
      export_name: z.string().optional().describe('Exported function name to resolve forwarder target for'),
    },
    async ({ action, module_name, export_name }) => {
      let data: unknown;
      switch (action) {
        case 'resolve_forwarder':
          data = await httpClient.post('/api/export_forward/resolve', { module_name, export_name });
          break;
        case 'scan_module_forwarders':
          data = await httpClient.post('/api/export_forward/scan_module', { module_name });
          break;
        case 'trace_forwarder_chain':
          data = await httpClient.post('/api/export_forward/trace_chain', { module_name, export_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
