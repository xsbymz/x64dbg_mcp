import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDotnetAppdomainMemoryDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_dotnet_appdomain_memory_dumper',
    'Dump isolated .NET AppDomains, HighFrequencyHeap, LowFrequencyHeap, and AssemblyLoader metadata memory blocks.',
    {
      action: z.enum(['list_appdomains', 'dump_loader_heaps', 'inspect_domain_assemblies']).describe('.NET AppDomain action'),
      domain_id: z.number().optional().describe('AppDomain ID or handle'),
    },
    async ({ action, domain_id }) => {
      let data: unknown;
      switch (action) {
        case 'list_appdomains':
          data = await httpClient.get('/api/clr_domain/list');
          break;
        case 'dump_loader_heaps':
          data = await httpClient.post('/api/clr_domain/loader_heaps', { domain_id });
          break;
        case 'inspect_domain_assemblies':
          data = await httpClient.post('/api/clr_domain/assemblies', { domain_id });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
