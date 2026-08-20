import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryTransitionFlightRecorderTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_transition_flight_recorder',
    'Memory protection transition flight recorder tracking RW- to R-X/RWX executions to auto-pause and auto-dump decrypted malware payloads.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('record_transitions')
        }),
        z.object({
          action: z.literal('auto_dump_payloads')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'record_transitions':
            data = await httpClient.post('/api/mem_flight/record_transitions', {});
            break;
          case 'auto_dump_payloads':
            data = await httpClient.post('/api/mem_flight/auto_dump_payloads', {});
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
