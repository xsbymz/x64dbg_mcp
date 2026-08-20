import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehFilterExpressionEvaluatorTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_filter_expression_evaluator',
    'Evaluate dynamic SEH filter expressions (EXCEPTION_EXECUTE_HANDLER, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_CONTINUE_EXECUTION) under current register context.',
    {
      action: z.enum(['evaluate_filter', 'simulate_exception_dispatch', 'get_disposition_name']).describe('Filter evaluator action'),
      filter_address: z.string().optional().describe('Address of the filter routine / expression'),
      exception_code: z.string().optional().describe('Exception code to pass into GetExceptionCode() (e.g. 0xC0000005)'),
    },
    async ({ action, filter_address, exception_code }) => {
      let data: unknown;
      switch (action) {
        case 'evaluate_filter':
          data = await httpClient.post('/api/seh_filter/evaluate', { filter_address, exception_code });
          break;
        case 'simulate_exception_dispatch':
          data = await httpClient.post('/api/seh_filter/simulate', { filter_address, exception_code });
          break;
        case 'get_disposition_name':
          data = await httpClient.post('/api/seh_filter/disposition', { exception_code });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
