import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWow64TransitionAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_wow64_transition_analyzer',
    'Analyze WOW64 32-bit to 64-bit mode switching (Heavens Gate far jump 0x33, Wow64Transition, and 64-bit TEB/PEB access from 32-bit processes).',
    {
      action: z.enum(['detect_heavens_gate', 'inspect_wow64_cpu', 'get_wow64_teb64']).describe('WOW64 action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'detect_heavens_gate':
          data = await httpClient.get('/api/wow64/heavens_gate');
          break;
        case 'inspect_wow64_cpu':
          data = await httpClient.get('/api/wow64/cpu_state');
          break;
        case 'get_wow64_teb64':
          data = await httpClient.get('/api/wow64/teb64');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
