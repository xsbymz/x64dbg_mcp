import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEtwAmsiTools(server: McpServer) {
  server.tool(
    'x64dbg_etw_amsi',
    'Detect ETW/AMSI bypass techniques. Checks for patched AmsiScanBuffer, NtTraceEvent, ' +
    'disabled ETW callbacks, and hooked Etwp* functions. Identifies INT3 patches, inline JMP hooks, ' +
    'and unexpected modifications to security-critical stubs.',
    {},
    async () => {
      try {
        const data = await httpClient.get('/api/etw_amsi/detect');
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
