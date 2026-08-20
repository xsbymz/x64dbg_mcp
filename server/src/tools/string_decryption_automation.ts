import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStringDecryptionTools(server: McpServer) {
  server.tool(
    'x64dbg_string_decryption_automation',
    'Automatic string decryption engine. Identifies encrypted strings and automatically decrypts them using pattern recognition and execution tracing. ' +
    'Supports XOR, RC4, custom transforms, and custom decryption routines. ' +
    'Actions: find_encrypted_strings (identify encrypted regions), decrypt_string (decrypt specific string), ' +
    'auto_decrypt_all (find and decrypt all strings).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('find_encrypted_strings'),
          entropy_threshold: z.number().optional().default(6.5).describe('Entropy threshold (0-8)'),
          min_length: z.number().optional().default(16).describe('Minimum string length'),
          module: z.string().optional().describe('Module to scan (all if omitted)')
        }),
        z.object({
          action: z.literal('decrypt_string'),
          address: z.string().describe('Encrypted string address'),
          method: z.enum(['xor', 'rc4', 'custom_routine', 'auto_detect']).optional().default('auto_detect').describe('Decryption method'),
          decryption_routine: z.string().optional().describe('Custom routine address if method=custom_routine'),
          key: z.string().optional().describe('Encryption key (if known, hex format)')
        }),
        z.object({
          action: z.literal('auto_decrypt_all'),
          scan_memory: z.boolean().optional().default(true).describe('Scan all memory regions'),
          scan_modules: z.boolean().optional().default(true).describe('Scan module .data sections'),
          entropy_threshold: z.number().optional().default(6.5).describe('Entropy threshold'),
          timeout_seconds: z.number().optional().default(30).describe('Timeout for decryption')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'find_encrypted_strings':
            data = await httpClient.post('/api/strings/find_encrypted', {
              entropy_threshold: action.entropy_threshold,
              min_length: action.min_length,
              module: action.module
            });
            break;
          case 'decrypt_string':
            data = await httpClient.post('/api/strings/decrypt', {
              address: action.address,
              method: action.method,
              decryption_routine: action.decryption_routine,
              key: action.key
            });
            break;
          case 'auto_decrypt_all':
            data = await httpClient.post('/api/strings/auto_decrypt_all', {
              scan_memory: action.scan_memory,
              scan_modules: action.scan_modules,
              entropy_threshold: action.entropy_threshold,
              timeout_seconds: action.timeout_seconds
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
