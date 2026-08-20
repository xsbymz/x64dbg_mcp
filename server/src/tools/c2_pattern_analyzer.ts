import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerC2PatternAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_c2_pattern_analyzer',
    'Analyze malware Command-and-Control (C2) communication patterns, heartbeat intervals, beaconing behaviors, and extract network IOCs from active debugging.',
    {
      action: z.enum(['detect_patterns', 'extract_ioc', 'analyze_traffic']).describe('Action to execute'),
      sample_duration_sec: z.number().optional().default(30),
    },
    async ({ action, sample_duration_sec }) => {
      let data: unknown;
      switch (action) {
        case 'detect_patterns':
          data = await httpClient.post('/api/c2/detect_patterns', { sample_duration_sec });
          break;
        case 'extract_ioc':
          data = await httpClient.post('/api/c2/extract_ioc', {});
          break;
        case 'analyze_traffic':
          data = await httpClient.get('/api/c2/analyze_traffic');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
