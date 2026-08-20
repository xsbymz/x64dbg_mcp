import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFunctionPrototypeGeneratorTools(server: McpServer) {
  server.tool(
    'x64dbg_function_prototype_generator',
    'Synthesize complete C/C++ function prototype signatures and header declarations from observed live execution traces, argument registers, and return values.',
    {
      action: z.enum(['generate_prototype', 'generate_header_file', 'inspect_observed_types']).describe('Prototype generator action'),
      function_address: z.string().optional().describe('Target function address (defaults to CIP)'),
      function_name: z.string().optional().default('SubFunction').describe('Name for generated function prototype'),
    },
    async ({ action, function_address, function_name }) => {
      let data: unknown;
      switch (action) {
        case 'generate_prototype':
          data = await httpClient.post('/api/proto_gen/prototype', { function_address, function_name });
          break;
        case 'generate_header_file':
          data = await httpClient.post('/api/proto_gen/header', { function_address, function_name });
          break;
        case 'inspect_observed_types':
          data = await httpClient.post('/api/proto_gen/types', { function_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
