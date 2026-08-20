import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoAsymmetricKeyDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto_asymmetric_key_detector',
    'Scan memory for RSA public/private keys, PKCS#1 DER headers, and ECC elliptic curve point coordinates.',
    {
      action: z.enum(['scan_rsa_keys', 'scan_ecc_keys', 'inspect_pkcs1_header']).describe('Asymmetric crypto action'),
      address: z.string().optional().describe('Virtual address to inspect (scans all memory if omitted)'),
      size: z.number().optional().describe('Byte size of scan region'),
    },
    async ({ action, address, size }) => {
      let data: unknown;
      switch (action) {
        case 'scan_rsa_keys':
          data = await httpClient.post('/api/asym_crypto/rsa', { address, size });
          break;
        case 'scan_ecc_keys':
          data = await httpClient.post('/api/asym_crypto/ecc', { address, size });
          break;
        case 'inspect_pkcs1_header':
          data = await httpClient.post('/api/asym_crypto/pkcs1', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
