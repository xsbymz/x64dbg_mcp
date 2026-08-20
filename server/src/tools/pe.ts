import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeTools(server: McpServer) {
  server.tool(
    'x64dbg_pe',
    'Deep PE header, structure, and security mitigation inspection (Checksec). ' +
    'Extract TLS callbacks, entry point RVA/VA, all 15 standard PE Data Directories, and security hardening mitigations (ASLR, High Entropy VA, DEP/NX, SafeSEH, Control Flow Guard CFG, Stack Cookies /GS, AppContainer, Code Integrity).',
    {
      action: z.enum(['tls_callbacks', 'deep_info', 'entry_point', 'mitigations']).describe(
        'Action: mitigations (checksec binary hardening audit), tls_callbacks (enumerate TLS callback functions executed before main), deep_info (full PE data directories), entry_point (entry point VA & RVA)'
      ),
      module: z.string().describe('Target module name (e.g. "main.exe", "ntdll.dll")')
    },
    async ({ action, module }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'mitigations':
            data = await httpClient.get('/api/pe/mitigations', { module });
            break;
          case 'tls_callbacks':
            data = await httpClient.get('/api/pe/tls_callbacks', { module });
            break;
          case 'deep_info':
            data = await httpClient.get('/api/pe/deep_info', { module });
            break;
          case 'entry_point':
            data = await httpClient.get('/api/dump/entry_point', { module });
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
