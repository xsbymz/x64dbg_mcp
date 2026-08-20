import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerObfuscationTools(server: McpServer) {
  server.tool(
    'x64dbg_obfuscation',
    'Obfuscation technique detection and analysis: CFG flattening, opaque predicates, VM detection, string decryption, and control flow analysis.',
    {
      action: z.enum(['detect', 'vm_detect', 'string_decrypt', 'opaque_predicates', 'flattening', 'loops', 'branch_analysis', 'indirect_calls']).describe('Analysis type'),
      address: z.string().optional().describe('Memory address or expression to analyze'),
      module: z.string().optional().describe('Module name'),
      count: z.number().optional().default(64).describe('Instructions to scan')
    },
    async ({ action, address, module, count }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};
        if (address) params.address = address;
        if (module) params.module = module;
        if (count !== undefined) params.count = String(count);

        if (action === 'flattening' || action === 'loops' || action === 'branch_analysis') {
          data = await httpClient.get(`/api/cfg/${action}`, params);
        } else if (action === 'indirect_calls') {
          data = await httpClient.get('/api/cfg/indirect_calls', params);
        } else {
          data = await httpClient.get(`/api/obfuscation/${action}`, params);
        }

        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
