import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTlsKeyExtractorTools(server: McpServer) {
  server.tool(
    'x64dbg_tls_key_extractor',
    'Dynamic TLS / SSL master key extractor (Schannel, OpenSSL, BoringSSL) and Wireshark SSLKEYLOGFILE generator.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('hook_schannel')
        }),
        z.object({
          action: z.literal('hook_openssl')
        }),
        z.object({
          action: z.literal('export_sslkeylog')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'hook_schannel':
            data = await httpClient.post('/api/tls/hook_schannel', {});
            break;
          case 'hook_openssl':
            data = await httpClient.post('/api/tls/hook_openssl', {});
            break;
          case 'export_sslkeylog':
            data = await httpClient.post('/api/tls/export_sslkeylog', {});
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
