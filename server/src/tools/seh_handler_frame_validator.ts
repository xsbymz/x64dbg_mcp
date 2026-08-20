import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehHandlerFrameValidatorTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_handler_frame_validator',
    'Validate SEH handler pointers against SafeSEH table, CFG valid call targets, and memory execution permissions.',
    {
      action: z.enum(['validate_handler', 'check_safeseh_table', 'scan_stack_handlers']).describe('Handler validation action'),
      handler_address: z.string().optional().describe('Virtual address of exception handler'),
      module_name: z.string().optional().describe('Module name for SafeSEH checking'),
    },
    async ({ action, handler_address, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'validate_handler':
          data = await httpClient.post('/api/seh_val/validate', { handler_address });
          break;
        case 'check_safeseh_table':
          data = await httpClient.post('/api/seh_val/safeseh', { module_name });
          break;
        case 'scan_stack_handlers':
          data = await httpClient.get('/api/seh_val/stack');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
