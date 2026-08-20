import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerIatHashTools(server: McpServer) {
  server.tool(
    'x64dbg_iathash',
    'Calculate import/export address table hashes for malware family identification. ' +
    'Actions: iat (CRC32 + FNV-1a hash of Import Address Table entries), ' +
    'eat (CRC32 + FNV-1a hash of Export Address Table entries).',
    {
      action: z.enum(['iat', 'eat']).describe('Hash type'),
      module: z.string().describe('Module name (e.g. "target.exe", "ntdll.dll")')
    },
    async ({ action, module }) => {
      try {
        const data = await httpClient.get(action === 'iat' ? '/api/iathash' : '/api/eathash', { module });
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
