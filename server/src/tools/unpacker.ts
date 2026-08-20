import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerUnpackerTools(server: McpServer) {
  server.tool(
    'x64dbg_unpacker',
    'Automated unpacker and OEP finder. ' +
    'Actions: auto (iterative unpacking: set execute BP, run, detect tail jumps, dump, validate IAT), ' +
    'entry_candidates (scan module for potential OEP candidates by finding tail jumps to high addresses).',
    {
      action: z.enum(['auto', 'entry_candidates']).describe('Unpacker action'),
      module: z.string().optional().describe('Module name (optional for auto, required for entry_candidates)'),
      max_iterations: z.number().optional().default(5).describe('Max unpacking iterations (auto action)'),
      oep_hint: z.string().optional().describe('Optional OEP address hint (hex, auto action)')
    },
    async ({ action, module, max_iterations, oep_hint }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'auto':
            data = await httpClient.post('/api/unpacker/auto', {
              module: module || 'main.exe',
              max_iterations,
              oep_hint: oep_hint || ''
            });
            break;
          case 'entry_candidates':
            if (!module) throw new Error('module is required for entry_candidates action');
            data = await httpClient.get('/api/unpacker/entry_candidates', { module });
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
