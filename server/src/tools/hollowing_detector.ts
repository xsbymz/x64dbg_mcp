import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHollowingDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hollowing_detector',
    'Enhanced process hollowing detection and analysis. Identify signs of process hollowing, DLL injection, code hollowing, and PE header manipulation. ' +
    'Actions: analyze_module (deep module analysis), detect_hollowing (find hollowing indicators), verify_integrity (validate module authenticity).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('analyze_module'),
          module: z.string().describe('Module name to analyze (e.g., "target.exe", "ntdll.dll")'),
          check_pe_header: z.boolean().optional().default(true).describe('Verify PE header integrity'),
          check_sections: z.boolean().optional().default(true).describe('Compare sections vs disk'),
          check_exports: z.boolean().optional().default(true).describe('Verify export table'),
          check_iat: z.boolean().optional().default(true).describe('Verify Import Address Table')
        }),
        z.object({
          action: z.literal('detect_hollowing'),
          aggressive: z.boolean().optional().default(false).describe('Use aggressive heuristics'),
          include_section_mismatch: z.boolean().optional().default(true).describe('Flag section mismatches'),
          include_entry_point_anomalies: z.boolean().optional().default(true).describe('Check for suspicious entry points'),
          include_memory_gaps: z.boolean().optional().default(true).describe('Detect memory gaps/missing sections')
        }),
        z.object({
          action: z.literal('verify_integrity'),
          module: z.string().describe('Module to verify'),
          use_disk_copy: z.boolean().optional().default(true).describe('Compare against disk copy'),
          check_hash: z.boolean().optional().default(true).describe('Verify module hash/signature'),
          report_differences: z.boolean().optional().default(true).describe('Report all differences found')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'analyze_module':
            data = await httpClient.post('/api/hollowing/analyze', {
              module: action.module,
              check_pe_header: action.check_pe_header,
              check_sections: action.check_sections,
              check_exports: action.check_exports,
              check_iat: action.check_iat
            });
            break;
          case 'detect_hollowing':
            data = await httpClient.post('/api/hollowing/detect', {
              aggressive: action.aggressive,
              include_section_mismatch: action.include_section_mismatch,
              include_entry_point_anomalies: action.include_entry_point_anomalies,
              include_memory_gaps: action.include_memory_gaps
            });
            break;
          case 'verify_integrity':
            data = await httpClient.post('/api/hollowing/verify', {
              module: action.module,
              use_disk_copy: action.use_disk_copy,
              check_hash: action.check_hash,
              report_differences: action.report_differences
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
