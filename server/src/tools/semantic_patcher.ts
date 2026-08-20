import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSemanticPatcherTools(server: McpServer) {
  server.tool(
    'x64dbg_semantic_patcher',
    'Semantic-aware binary patching with automatic validation and conflict detection. ' +
    'Generates minimal patches that preserve code semantics while fixing vulnerabilities or adding functionality. ' +
    'Actions: suggest_patch (recommend patch strategy), apply_semantic_patch (validate and apply), ' +
    'detect_patch_conflicts (find incompatible patches).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('suggest_patch'),
          target_address: z.string().describe('Code address to patch'),
          patch_type: z.enum(['security_fix', 'nop_vulnerable', 'jump_over', 'replace_function', 'add_check']).describe('Type of patch'),
          desired_effect: z.string().optional().describe('Semantic goal of patch'),
          constraints: z.array(z.string()).optional().describe('Constraints (size, register preservation, etc)')
        }),
        z.object({
          action: z.literal('apply_semantic_patch'),
          address: z.string().describe('Address to patch'),
          patch_bytes: z.string().describe('New bytes (hex)'),
          original_bytes: z.string().describe('Original bytes (for validation)'),
          semantic_validation: z.boolean().optional().default(true).describe('Validate semantic equivalence')
        }),
        z.object({
          action: z.literal('detect_patch_conflicts'),
          patches: z.array(z.object({
            address: z.string().describe('Patch address'),
            bytes: z.string().describe('New bytes (hex)')
          })).describe('Proposed patches'),
          report_overlaps: z.boolean().optional().default(true).describe('Report overlapping patches'),
          report_semantic_conflicts: z.boolean().optional().default(true).describe('Detect semantic conflicts')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'suggest_patch':
            data = await httpClient.post('/api/patch/suggest_patch', {
              target_address: action.target_address,
              patch_type: action.patch_type,
              desired_effect: action.desired_effect,
              constraints: action.constraints
            });
            break;
          case 'apply_semantic_patch':
            data = await httpClient.post('/api/patch/apply_semantic', {
              address: action.address,
              patch_bytes: action.patch_bytes,
              original_bytes: action.original_bytes,
              semantic_validation: action.semantic_validation
            });
            break;
          case 'detect_patch_conflicts':
            data = await httpClient.post('/api/patch/detect_conflicts', {
              patches: action.patches,
              report_overlaps: action.report_overlaps,
              report_semantic_conflicts: action.report_semantic_conflicts
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
