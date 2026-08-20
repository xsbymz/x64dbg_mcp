import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEtwTraceSessionEnumeratorTools(server: McpServer) {
  server.tool(
    'x64dbg_etw_trace_session_enumerator',
    'Enumerate all active kernel and user ETW trace sessions (NT Kernel Logger, EventLog-Security, Defender traces) and session buffer stats.',
    {
      action: z.enum(['enum_active_sessions', 'get_session_details', 'get_kernel_logger_stats']).describe('ETW session action'),
      session_name: z.string().optional().describe('ETW Session Name string'),
    },
    async ({ action, session_name }) => {
      let data: unknown;
      switch (action) {
        case 'enum_active_sessions':
          data = await httpClient.get('/api/etw_sessions/list');
          break;
        case 'get_session_details':
          data = await httpClient.post('/api/etw_sessions/details', { session_name });
          break;
        case 'get_kernel_logger_stats':
          data = await httpClient.get('/api/etw_sessions/kernel_logger');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
