import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVehTools(server: McpServer) {
  server.tool(
    'x64dbg_veh',
    'Vectored Exception Handling (VEH) chain enumeration. ' +
    'Walks the PEB VectoredHandlerList to find registered vectored exception handlers. ' +
    'Detects both vectored continue handlers and vectored exception handlers.',
    {},
    async () => {
      try {
        const data = await httpClient.get('/api/veh/chain');
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
