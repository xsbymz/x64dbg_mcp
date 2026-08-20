import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSecurityTools(server: McpServer) {
  server.tool(
    'x64dbg_security',
    'Security analysis: stack canary detection, anti-debug checks, and exploitability scoring.',
    {
      action: z.enum(['status', 'verify_token', 'hardening_report', 'stack_canary_analyze', 'scan_all_functions_canary']).describe('Security action'),
      module: z.string().optional().describe('Module name (for stack_canary_analyze and scan_all_functions_canary)'),
      function_address: z.string().optional().describe('Function address or name (for stack_canary_analyze)')
    },
    async ({ action, module, function_address }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'status':
            data = await httpClient.get('/api/security/status');
            break;
          case 'verify_token':
            data = await httpClient.get('/api/security/verify_token');
            break;
          case 'hardening_report':
            data = await httpClient.get('/api/security/hardening_report');
            break;
          case 'stack_canary_analyze':
            if (!function_address) throw new Error('function_address is required for stack_canary_analyze');
            data = await httpClient.post('/api/security/stack_canary_analyze', {
              module: module || '',
              function_address
            });
            break;
          case 'scan_all_functions_canary':
            if (!module) throw new Error('module is required for scan_all_functions_canary');
            data = await httpClient.post('/api/security/scan_all_functions_canary', { module });
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
