import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSymbolicTaintFlowSynthesizerTools(server: McpServer) {
  server.tool(
    'x64dbg_symbolic_taint_flow_synthesizer',
    'Synthesize symbolic path constraint equations linking user-controlled taint sources to critical security sinks (RIP hijacking, arbitrary write pointers).',
    {
      action: z.enum(['synthesize_flow_constraints', 'check_sink_reachability', 'solve_exploit_input']).describe('Taint flow action'),
      source_address: z.string().optional().describe('Taint source virtual address or buffer'),
      sink_address: z.string().optional().describe('Security sink virtual address (e.g. indirect call / ret / write ptr)'),
    },
    async ({ action, source_address, sink_address }) => {
      let data: unknown;
      switch (action) {
        case 'synthesize_flow_constraints':
          data = await httpClient.post('/api/taint_synth/constraints', { source_address, sink_address });
          break;
        case 'check_sink_reachability':
          data = await httpClient.post('/api/taint_synth/reachability', { source_address, sink_address });
          break;
        case 'solve_exploit_input':
          data = await httpClient.post('/api/taint_synth/solve', { source_address, sink_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
