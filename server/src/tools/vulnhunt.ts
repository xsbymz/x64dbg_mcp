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
    'vulnhunt_format_string',
    'Scan a module for format string vulnerability candidates. ' +
    'Finds calls to printf/sprintf/wprintf/DbgPrint where the format argument ' +
    'does not appear to be a constant string literal (potential user-controlled input). ' +
    'Returns {address, instruction, severity, confidence} per finding.',
    CommonParams,
    async ({ module, limit }) => {
      const data = await httpClient.post('/api/vulnhunt/format_string_scan', { module, limit });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_stack_frames',
    'Scan a module for functions with dangerously large stack frames. ' +
    'Flags "sub rsp, N" prologues where N >= threshold, and dynamic alloca/VLA patterns. ' +
    'Large frames can be exploited via stack overflow or are indicators of unsafe local buffers.',
    {
      ...CommonParams,
      threshold: z.number().int().min(64).optional().default(4096)
                  .describe('Minimum frame size (bytes) to flag as suspicious'),
    },
    async ({ module, limit, threshold }) => {
      const data = await httpClient.post('/api/vulnhunt/stack_frame_scan', {
        module, limit, threshold,
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_integer_overflow',
    'Scan for integer overflow candidates before size-based allocations. ' +
    'Detects patterns like: imul/mul/shl/add instruction within 8 instructions before ' +
    'a call to malloc/HeapAlloc/VirtualAlloc/memcpy. ' +
    'These patterns can lead to under-allocated buffers followed by heap overflow.',
    CommonParams,
    async ({ module, limit }) => {
      const data = await httpClient.post('/api/vulnhunt/overflow_scan', { module, limit });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_heap_spray',
    'Detect heap spray patterns by analyzing the live heap allocation map. ' +
    'Flags groups of N or more allocations of the same size, especially those ' +
    'filled with NOP sleds (0x90), shellcode fill bytes (0x0D, 0x41), or other patterns. ' +
    'Requires an active debug session (not necessarily paused).',
    {
      pattern_threshold: z.number().int().min(5).optional().default(50)
                          .describe('Minimum count of same-size allocations to flag as spray'),
      size_bucket_min:   z.number().int().min(16).optional().default(256)
                          .describe('Minimum allocation size (bytes) to consider in spray analysis'),
    },
    async ({ pattern_threshold, size_bucket_min }) => {
      const data = await httpClient.post('/api/vulnhunt/heap_spray_detect', {
        pattern_threshold, size_bucket_min,
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_use_after_free',
    'Static heuristic scan for use-after-free candidates. ' +
    'Finds HeapFree/free calls within functions, tracks the freed register, ' +
    'and flags any subsequent dereference of that same register. ' +
    'NOTE: Static analysis only — expect false positives. Confidence ~0.55. ' +
    'Use dynamic analysis to confirm.',
    CommonParams,
    async ({ module, limit }) => {
      const data = await httpClient.post('/api/vulnhunt/uaf_scan', { module, limit });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'vulnhunt_summary',
    'Get an overview of all available vulnerability scanning endpoints for a module. ' +
    'Run individual scans via vulnhunt_format_string, vulnhunt_stack_frames, ' +
    'vulnhunt_integer_overflow, vulnhunt_heap_spray, and vulnhunt_use_after_free.',
    {
      module: z.string().optional().describe('Module name (default: module at CIP)'),
    },
    async ({ module }) => {
      const params: Record<string, string> = {};
      if (module) params.module = module;
      const data = await httpClient.get('/api/vulnhunt/summary', params);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
