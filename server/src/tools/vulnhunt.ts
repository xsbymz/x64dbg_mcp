import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

const CommonParams = {
  module: z.string().optional().describe('Module to scan (default: module at CIP)'),
  limit:  z.number().int().min(1).max(2000).optional().default(200)
           .describe('Maximum number of findings to return'),
};

export function registerVulnHuntTools(server: McpServer) {
  server.tool(
    'vulnhunt_scan_patterns',
    'Scan a module for vulnerability patterns: unsafe functions, format strings, heap issues, and stack canary presence.',
    CommonParams,
    async ({ module, limit }) => {
      const data = await httpClient.post('/api/vuln/scan_patterns', { module, limit });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_buffer_overflow',
    'Check a specific function for buffer overflow candidates: unsafe strcpy/strcat/sprintf, missing length checks.',
    {
      function: z.string().describe('Function name or address to analyze')
    },
    async ({ function: func }) => {
      const data = await httpClient.post('/api/vuln/check_buffer_overflow', { function: func });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_format_string',
    'Check a specific function for format string vulnerabilities: printf-family calls with non-literal format.',
    {
      function: z.string().describe('Function name or address to analyze')
    },
    async ({ function: func }) => {
      const data = await httpClient.post('/api/vuln/check_format_string', { function: func });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_integer_overflow',
    'Check a specific function for integer overflow candidates before size-based allocations.',
    {
      function: z.string().describe('Function name or address to analyze')
    },
    async ({ function: func }) => {
      const data = await httpClient.post('/api/vuln/check_integer_overflow', { function: func });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_stack_canary',
    'Check a specific function for stack canary (stack cookie) protection: __security_cookie load and __stack_chk_fail check.',
    {
      function: z.string().describe('Function name or address to analyze')
    },
    async ({ function: func }) => {
      const data = await httpClient.post('/api/vuln/stack_canary_check', { function: func });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_exploitability_score',
    'Compute an exploitability score for a function based on detected vulnerability patterns and stack canary status.',
    {
      function: z.string().describe('Function name or address to analyze')
    },
    async ({ function: func }) => {
      const data = await httpClient.post('/api/vuln/exploitability_score', { function: func });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
