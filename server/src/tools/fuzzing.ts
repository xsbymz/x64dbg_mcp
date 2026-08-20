import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFuzzingTools(server: McpServer) {
  server.tool(
    'x64dbg_fuzz',
    'Fuzzing harness and crash triage: create harnesses, run iterations, analyze crashes, and track coverage.',
    {
      action: z.enum(['harness', 'iterate', 'crash_triage', 'coverage', 'stop']).describe('Fuzzing action'),
      target_path: z.string().optional().describe('Path to target binary (harness action)'),
      harness_id: z.string().optional().describe('Harness ID (iterate, crash_triage, coverage, stop actions)'),
      input_data: z.string().optional().describe('Hex or string input (iterate action)'),
      crash_id: z.string().optional().describe('Crash ID (crash_triage action)'),
      timeout_ms: z.number().optional().default(5000).describe('Execution timeout in milliseconds'),
      max_iterations: z.number().optional().default(100).describe('Maximum iterations')
    },
    async ({ action, target_path, harness_id, input_data, crash_id, timeout_ms, max_iterations }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};

        switch (action) {
          case 'harness':
            if (!target_path) throw new Error('target_path is required for harness action');
            data = await httpClient.post('/api/fuzz/harness', {
              target_path,
              timeout_ms,
              max_iterations
            });
            break;
          case 'iterate':
            if (!harness_id) throw new Error('harness_id is required for iterate action');
            data = await httpClient.post('/api/fuzz/iterate', {
              harness_id,
              input_data: input_data || ''
            });
            break;
          case 'crash_triage':
            if (!harness_id || !crash_id) throw new Error('harness_id and crash_id are required for crash_triage action');
            data = await httpClient.get('/api/fuzz/crash_triage', { harness_id, crash_id });
            break;
          case 'coverage':
            if (!harness_id) throw new Error('harness_id is required for coverage action');
            data = await httpClient.get('/api/fuzz/coverage', { harness_id });
            break;
          case 'stop':
            if (!harness_id) throw new Error('harness_id is required for stop action');
            data = await httpClient.post('/api/fuzz/stop', { harness_id });
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
