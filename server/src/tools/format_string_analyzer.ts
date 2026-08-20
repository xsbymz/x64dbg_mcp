import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFormatStringAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_format_string_analyzer',
    'Automated Format String Vulnerability & Exploitation Payload Synthesizer. Detect insecure format specifiers, calculate positional parameter offsets, and generate arbitrary write payloads.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_vulnerabilities')
        }),
        z.object({
          action: z.literal('calculate_offset'),
          pattern: z.string().describe('Probe pattern used (e.g. "AAAA%p%p%p%p%p%p%p%p")'),
          target_token: z.string().describe('Token to locate in output (e.g. "0x41414141")')
        }),
        z.object({
          action: z.literal('generate_payload'),
          target_address: z.string().describe('Memory address to overwrite (e.g. "0x405000")'),
          target_value: z.string().describe('Value to write (e.g. "0x401234")'),
          offset: z.number().describe('Positional parameter offset')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_vulnerabilities':
            data = await httpClient.post('/api/format_string/scan', {});
            break;
          case 'calculate_offset':
            data = await httpClient.post('/api/format_string/offset_calc', {
              pattern: action.pattern,
              target_token: action.target_token
            });
            break;
          case 'generate_payload':
            data = await httpClient.post('/api/format_string/payload_gen', {
              target_address: action.target_address,
              target_value: action.target_value,
              offset: action.offset
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
