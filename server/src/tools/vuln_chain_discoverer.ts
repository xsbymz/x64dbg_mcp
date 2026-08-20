import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVulnChainDiscovererTools(server: McpServer) {
  server.tool(
    'x64dbg_vuln_chain_discoverer',
    'Automatically synthesize multi-stage exploit chains linking individual primitives (Information Leak -> ASLR Bypass -> Arbitrary Write -> Control Flow Hijack).',
    {
      action: z.enum(['discover_chains', 'link_primitives', 'validate_path']).describe('Vulnerability chain discovery action'),
      target_outcome: z.enum(['rce', 'lpe', 'sandbox_escape', 'info_disclosure']).optional().default('rce'),
    },
    async ({ action, target_outcome }) => {
      let data: unknown;
      switch (action) {
        case 'discover_chains':
          data = await httpClient.post('/api/vulnchain/discover_chains', { target_outcome });
          break;
        case 'link_primitives':
          data = await httpClient.post('/api/vulnchain/link_primitives', {});
          break;
        case 'validate_path':
          data = await httpClient.post('/api/vulnchain/validate_path', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
