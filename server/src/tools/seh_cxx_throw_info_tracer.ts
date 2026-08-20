import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehCxxThrowInfoTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_cxx_throw_info_tracer',
    'Trace MSVC C++ _CxxThrowException invocations, _ThrowInfo structures, CatchableType arrays, and RTTI exception type descriptors.',
    {
      action: z.enum(['parse_throw_info', 'get_catchable_types', 'trace_active_exception']).describe('ThrowInfo action'),
      throw_info_ptr: z.string().optional().describe('Virtual address of _ThrowInfo descriptor'),
      exception_object_ptr: z.string().optional().describe('Virtual address of thrown exception object'),
    },
    async ({ action, throw_info_ptr, exception_object_ptr }) => {
      let data: unknown;
      switch (action) {
        case 'parse_throw_info':
          data = await httpClient.post('/api/cxx_throw/parse', { throw_info_ptr });
          break;
        case 'get_catchable_types':
          data = await httpClient.post('/api/cxx_throw/catchable_types', { throw_info_ptr });
          break;
        case 'trace_active_exception':
          data = await httpClient.post('/api/cxx_throw/active', { exception_object_ptr, throw_info_ptr });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
