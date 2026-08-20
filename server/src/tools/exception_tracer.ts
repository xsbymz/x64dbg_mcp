import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerExceptionTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_exception_tracer',
    'Trace and analyze user-mode structured exception handling (SEH, VEH, UVEH), inspect KiUserExceptionDispatcher frames, and evaluate nested exception handlers.',
    {
      action: z.enum(['trace_last_exception', 'inspect_seh_chain', 'inspect_veh_chain', 'dump_context_record']).describe('Exception analysis action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'trace_last_exception':
          data = await httpClient.get('/api/exception_trace/last');
          break;
        case 'inspect_seh_chain':
          data = await httpClient.get('/api/exception_trace/seh');
          break;
        case 'inspect_veh_chain':
          data = await httpClient.get('/api/exception_trace/veh');
          break;
        case 'dump_context_record':
          data = await httpClient.get('/api/exception_trace/context');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
