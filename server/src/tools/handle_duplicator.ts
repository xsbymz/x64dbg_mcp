import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHandleDuplicatorTools(server: McpServer) {
  server.tool(
    'x64dbg_handle_duplicator',
    'Duplicate, inspect, or elevate access masks on target process object handles (processes, threads, events, mutexes, file handles) using DuplicateHandle.',
    {
      action: z.enum(['duplicate_handle', 'inspect_handle_rights', 'close_target_handle']).describe('Handle action'),
      handle_value: z.number().describe('Target handle numeric value'),
      desired_access: z.string().optional().describe('Desired access mask hex (e.g. 0x1F0FFF for PROCESS_ALL_ACCESS)'),
    },
    async ({ action, handle_value, desired_access }) => {
      let data: unknown;
      switch (action) {
        case 'duplicate_handle':
          data = await httpClient.post('/api/handle_dup/duplicate', { handle_value, desired_access });
          break;
        case 'inspect_handle_rights':
          data = await httpClient.post('/api/handle_dup/inspect', { handle_value });
          break;
        case 'close_target_handle':
          data = await httpClient.post('/api/handle_dup/close', { handle_value });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
