import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMinidumpGeneratorTools(server: McpServer) {
  server.tool(
    'x64dbg_minidump_generator',
    'Generate Windows crash minidumps (.dmp) of debuggee with MiniDumpWithFullMemory, MiniDumpWithThreadInfo, or MiniDumpWithHandleData.',
    {
      action: z.enum(['create_minidump', 'create_full_dump', 'get_dump_status']).describe('Dump generation action'),
      output_path: z.string().optional().describe('Target .dmp file path'),
    },
    async ({ action, output_path }) => {
      let data: unknown;
      switch (action) {
        case 'create_minidump':
          data = await httpClient.post('/api/dump/minidump', { output_path });
          break;
        case 'create_full_dump':
          data = await httpClient.post('/api/dump/fulldump', { output_path });
          break;
        case 'get_dump_status':
          data = await httpClient.get('/api/dump/status');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
