import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFlsFiberInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_fls_fiber_inspector',
    'Inspect Win32 user-mode Fibers and Fiber Local Storage (FLS): enumerate active fibers, fiber context registers, fiber stack limits, and FLS callback function pointers.',
    {
      action: z.enum(['list_fibers', 'get_fls_callbacks', 'inspect_current_fiber']).describe('Fiber inspection action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_fibers':
          data = await httpClient.get('/api/fiber/list');
          break;
        case 'get_fls_callbacks':
          data = await httpClient.get('/api/fiber/fls_callbacks');
          break;
        case 'inspect_current_fiber':
          data = await httpClient.get('/api/fiber/current');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
