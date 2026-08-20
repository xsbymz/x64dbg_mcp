import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWow64FsRedirectionInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_wow64_fs_redirection_inspector',
    'Query and inspect WOW64 File System Redirection state (SysWOW64 vs System32, Wow64DisableFsRedirection status, Wow64RevertFsRedirection).',
    {
      action: z.enum(['get_redirection_state', 'simulate_redirected_path', 'list_redirected_directories']).describe('FS redirection action'),
      path: z.string().optional().describe('Target file path to test (e.g. C:\\Windows\\System32\\kernel32.dll)'),
    },
    async ({ action, path }) => {
      let data: unknown;
      switch (action) {
        case 'get_redirection_state':
          data = await httpClient.get('/api/wow64_fs/state');
          break;
        case 'simulate_redirected_path':
          data = await httpClient.post('/api/wow64_fs/simulate', { path });
          break;
        case 'list_redirected_directories':
          data = await httpClient.get('/api/wow64_fs/directories');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
