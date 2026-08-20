import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerApiCallSynthesizerTools(server: McpServer) {
  server.tool(
    'x64dbg_api_call_synthesizer',
    'Synthesize and simulate execution of arbitrary Win32 API functions within the target process context with structured argument marshaling.',
    {
      action: z.enum(['simulate_call', 'list_supported_apis']).describe('Synthesizer action'),
      api_name: z.string().optional().describe('API name (e.g. kernel32.dll!GetCurrentProcessId)'),
      args: z.array(z.string()).optional().describe('List of argument values/expressions'),
    },
    async ({ action, api_name, args }) => {
      let data: unknown;
      switch (action) {
        case 'simulate_call':
          data = await httpClient.post('/api/api_synth/simulate', { api_name, args });
          break;
        case 'list_supported_apis':
          data = await httpClient.get('/api/api_synth/supported');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
