import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStringXrefTools(server: McpServer) {
  server.tool(
    'stringxref_find',
    'Find all instructions in a module that reference a specific string literal. ' +
    'Searches for the string in memory (ASCII and wide), then looks up xrefs to those addresses. ' +
    'Returns {address, instruction, type, module} for each referencing instruction.',
    {
      value:  z.string().max(512).describe('String literal to search for (e.g. "CreateFile", "SOFTWARE\\\\")'),
      module: z.string().optional().describe('Module to search in (default: module at CIP)'),
      case:   z.boolean().optional().default(false).describe('Case-sensitive search'),
    },
    async ({ value, module, case: caseSensitive }) => {
      const data = await httpClient.get('/api/stringxref/find', {
        value,
        ...(module ? { module } : {}),
        case: String(caseSensitive),
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'stringxref_all',
    'Enumerate all strings in a module and return which instructions reference each one. ' +
    'Only includes strings that have at least one cross-reference. ' +
    'Useful for mapping API usage patterns and finding interesting string-driven code paths.',
    {
      module: z.string().optional().describe('Module name (default: module at CIP)'),
      limit:  z.number().int().min(1).max(2000).optional().default(200)
               .describe('Maximum number of string entries to return'),
    },
    async ({ module, limit }) => {
      const params: Record<string, string> = { limit: String(limit) };
      if (module) params.module = module;
      const data = await httpClient.get('/api/stringxref/all', params);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'stringxref_annotate',
    'Auto-annotate all instructions in a module that reference string literals. ' +
    'Sets a comment on each referencing instruction with a preview of the string. ' +
    'Also comments the string\'s own VA with its full content.',
    {
      module: z.string().optional().describe('Module name (default: module at CIP)'),
      prefix: z.string().optional().default('s_').describe('Prefix for auto-generated comments'),
      limit:  z.number().int().min(1).max(2000).optional().default(500)
               .describe('Maximum number of strings to annotate'),
    },
    async ({ module, prefix, limit }) => {
      const data = await httpClient.post('/api/stringxref/annotate', { module, prefix, limit });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
