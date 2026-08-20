import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerApiLoggerTools(server: McpServer) {
  server.tool(
    'x64dbg_api_logger',
    'Deep API parameter logging and inspection. Capture function calls with full parameter inspection, return values, stack traces, and post-execution memory snapshots. ' +
    'Actions: setup (configure logging on API), inspect_last (inspect last captured call), dump_log (get all captured calls), clear (clear log).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('setup'),
          api_name: z.string().describe('API function name or address (e.g., "CreateFileA", "0x401000")'),
          module: z.string().optional().describe('Module to restrict to (e.g., "ntdll.dll")'),
          log_params: z.boolean().optional().default(true).describe('Log parameter values'),
          log_return: z.boolean().optional().default(true).describe('Log return value'),
          log_stack: z.boolean().optional().default(true).describe('Log call stack'),
          capture_memory: z.boolean().optional().default(false).describe('Capture memory at args after execution'),
          max_records: z.number().optional().default(100).describe('Max call records to keep')
        }),
        z.object({
          action: z.literal('inspect_last'),
          api_name: z.string().describe('API to inspect logs for')
        }),
        z.object({
          action: z.literal('dump_log'),
          api_name: z.string().optional().describe('Filter to specific API (all if omitted)'),
          format: z.enum(['json', 'text']).optional().default('json')
        }),
        z.object({
          action: z.literal('clear'),
          api_name: z.string().optional().describe('Clear specific API logs or all if omitted')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'setup':
            data = await httpClient.post('/api/telemetry/api_logger_setup', {
              api_name: action.api_name,
              module: action.module,
              log_params: action.log_params,
              log_return: action.log_return,
              log_stack: action.log_stack,
              capture_memory: action.capture_memory,
              max_records: action.max_records
            });
            break;
          case 'inspect_last':
            data = await httpClient.get('/api/telemetry/api_logger_inspect', { api_name: action.api_name });
            break;
          case 'dump_log':
            const params: Record<string, string> = { format: action.format };
            if (action.api_name) params.api_name = action.api_name;
            data = await httpClient.get('/api/telemetry/api_logger_dump', params);
            break;
          case 'clear':
            data = await httpClient.post('/api/telemetry/api_logger_clear', { 
              api_name: action.api_name || 'all'
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
