import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSessionTools(server: McpServer) {
  server.tool(
    'x64dbg_session',
    'Save and restore debugger sessions. ' +
    'Actions: save (export current session state: breakpoints, patches, labels, comments, bookmarks), ' +
    'restore (import session state from file), list (list saved sessions), delete (delete a saved session).',
    {
      action: z.enum(['save', 'restore', 'list', 'delete']).describe('Session action'),
      name: z.string().optional().describe('Session name (required for save, restore, delete)'),
      file: z.string().optional().describe('Session file path (restore only)')
    },
    async ({ action, name, file }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};
        if (name) params.name = name;
        if (file) params.file = file;

        switch (action) {
          case 'save':
            if (!name) throw new Error('name is required for save action');
            data = await httpClient.post('/api/session/save', { name });
            break;
          case 'restore':
            if (!name) throw new Error('name is required for restore action');
            data = await httpClient.post('/api/session/restore', { name, file: file || '' });
            break;
          case 'list':
            data = await httpClient.get('/api/session/list');
            break;
          case 'delete':
            if (!name) throw new Error('name is required for delete action');
            data = await httpClient.post('/api/session/delete', { name });
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
