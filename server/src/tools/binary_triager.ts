import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerBinaryTriagerTools(server: McpServer) {
  server.tool(
    'x64dbg_binary_triager',
    'Automated binary and threat triage engine: analyzes PE security mitigations, section entropy, dangerous API clusters, and maps findings to MITRE ATT&CK techniques.',
    {
      action: z.enum(['full_scan', 'security_matrix', 'mitre_mapping']).describe('Triage action'),
      module: z.string().optional().describe('Target module name (defaults to main module)'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'full_scan':
          data = await httpClient.post('/api/triage/full_scan', { module });
          break;
        case 'security_matrix':
          data = await httpClient.get('/api/triage/security_matrix', module ? { module } : undefined);
          break;
        case 'mitre_mapping':
          data = await httpClient.post('/api/triage/mitre_mapping', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
