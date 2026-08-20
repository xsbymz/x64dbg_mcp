import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessEnvironmentBlockDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_process_environment_block_dumper',
    'Complete structured JSON dump of RTL_USER_PROCESS_PARAMETERS (CommandLine, ImagePathName, DllPath, CurrentDirectory, WindowTitle, StandardHandles).',
    {
      action: z.enum(['dump_process_parameters', 'get_environment_variables', 'inspect_loader_lock_state']).describe('PEB dumper action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'dump_process_parameters':
          data = await httpClient.get('/api/peb_dump/parameters');
          break;
        case 'get_environment_variables':
          data = await httpClient.get('/api/peb_dump/environment');
          break;
        case 'inspect_loader_lock_state':
          data = await httpClient.get('/api/peb_dump/loader_lock');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
