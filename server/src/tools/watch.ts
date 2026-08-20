import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWatchTools(server: McpServer) {
  server.tool(
    'watch_add',
    'Add a named watch expression that tracks a register, memory address, or any x64dbg expression. ' +
    'The value is evaluated each time watch_list or watch_snapshot is called.',
    {
      name:       z.string().max(64).describe('Unique watch name (e.g. "heap_ptr", "eax_after_call")'),
      expression: z.string().max(256).describe('x64dbg expression to evaluate (e.g. "rax", "[rsp+8]", "mod.base(ntdll)")'),
      type:       z.enum(['hex', 'decimal', 'string_utf8', 'string_utf16', 'float'])
                   .optional().default('hex')
                   .describe('How to format the evaluated value'),
    },
    async ({ name, expression, type }) => {
      const data = await httpClient.post('/api/watch/add', { name, expression, type });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'watch_remove',
    'Remove a previously added watch expression by name.',
    { name: z.string().describe('Watch name to remove') },
    async ({ name }) => {
      const data = await httpClient.post('/api/watch/remove', { name });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'watch_list',
    'List all watches and their current evaluated values. Works best when debugger is paused.',
    {},
    async () => {
      const data = await httpClient.get('/api/watch/list');
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'watch_snapshot',
    'Evaluate all watch expressions right now and return a timestamped snapshot. ' +
    'Optionally also print each value to the x64dbg log window.',
    {
      log: z.boolean().optional().default(false).describe('If true, also print values to x64dbg log'),
    },
    async ({ log }) => {
      const data = await httpClient.get('/api/watch/snapshot', { log: String(log) });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'watch_diff',
    'Return only the watch expressions whose value changed since the last evaluation. ' +
    'Useful for spotting which variable was modified by the last step.',
    {},
    async () => {
      const data = await httpClient.get('/api/watch/diff');
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'watch_clear',
    'Remove all watch expressions.',
    {},
    async () => {
      const data = await httpClient.post('/api/watch/clear', {});
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
