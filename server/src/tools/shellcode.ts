import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerShellcodeTools(server: McpServer) {
  server.tool(
    'x64dbg_shellcode',
    'Shellcode execution harness: allocate memory, write shellcode, execute with optional single-stepping. ' +
    'Actions: execute (allocate memory, write hex bytes, run in target with trace capture), ' +
    'disassemble (linear disassembly of raw bytes at address, no function boundaries).',
    {
      action: z.enum(['execute', 'disassemble']).describe('Shellcode action'),
      bytes: z.string().describe('Hex bytes to execute (e.g. "90 90 CC")'),
      timeout_ms: z.number().optional().default(5000).describe('Max execution time in milliseconds'),
      single_step: z.boolean().optional().default(false).describe('Single-step through shellcode instead of running'),
      address: z.string().optional().describe('Address to disassemble (disassemble action)'),
      count: z.number().optional().default(20).describe('Instructions to disassemble (disassemble action)')
    },
    async ({ action, bytes, timeout_ms, single_step, address, count }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'execute':
            data = await httpClient.post('/api/shellcode/execute', {
              bytes,
              timeout_ms,
              single_step
            });
            break;
          case 'disassemble':
            if (!address) throw new Error('address is required for disassemble action');
            data = await httpClient.get('/api/shellcode/disassemble', {
              address,
              count: String(count ?? 20)
            });
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
