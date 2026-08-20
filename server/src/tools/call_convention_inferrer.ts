import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCallConventionInferrerTools(server: McpServer) {
  server.tool(
    'x64dbg_call_convention_inferrer',
    'Infer function calling conventions (__fastcall, __cdecl, __stdcall, __thiscall, __vectorcall) from stack cleanup, argument register usage, and callee-saved registers.',
    {
      action: z.enum(['infer_convention', 'inspect_parameters', 'inspect_return_type']).describe('Inference action'),
      address: z.string().optional().describe('Target function address (defaults to CIP)'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'infer_convention':
          data = await httpClient.post('/api/convention/infer', { address });
          break;
        case 'inspect_parameters':
          data = await httpClient.post('/api/convention/parameters', { address });
          break;
        case 'inspect_return_type':
          data = await httpClient.post('/api/convention/return_type', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
