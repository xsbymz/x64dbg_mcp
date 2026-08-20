import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSearchTools(server: McpServer) {
  server.tool(
    'x64dbg_search',
    'Search memory for byte patterns, strings, XOR-obfuscated strings, get string at address, symbol autocomplete. ' +
    'Actions: pattern (AOB / byte pattern scan with wildcard support, ?? = wildcard byte), ' +
    'string (search for ASCII/Unicode/UTF-8 string in memory — returns ALL matches with pagination), ' +
    'xor_scan (XOR brute-force scanner: test all 256 1-byte keys to find obfuscated/encrypted strings in malware or packed code), ' +
    'string_at (read string at a specific address), ' +
    'symbol_auto_complete (partial symbol name completion), ' +
    'encode_type (get the encoding type annotation at an address).',
    {
      action: z.discriminatedUnion("action", [
        z.object({
          action: z.literal("pattern"),
          query: z.string().describe("Byte pattern (e.g. '48 89 5C ??' or 'C4CB755B'). ?? = wildcard byte."),
          address: z.string().optional().describe("Restrict scan to start address (requires size)"),
          size: z.string().optional().describe("Restrict scan to byte range from address"),
          max_results: z.number().optional().default(1000).describe("Max total matches to find (capped at 10000)"),
          limit: z.number().optional().describe("Max matches to return in this response (pagination)"),
          offset: z.number().optional().default(0).describe("Skip first N matches (pagination)")
        }),
        z.object({
          action: z.literal("string"),
          query: z.string().describe("Text to search for"),
          module: z.string().optional().default("").describe("Restrict to module name, or empty for full memory scan"),
          encoding: z.enum(['utf8', 'ascii', 'unicode']).optional().default("utf8"),
          limit: z.number().optional().default(1000).describe("Max matches to return (pagination, max 5000)"),
          offset: z.number().optional().default(0).describe("Skip first N matches (pagination)")
        }),
        z.object({
          action: z.literal("xor_scan"),
          query: z.string().describe("Target string to search for under all 256 single-byte XOR encodings"),
          module: z.string().optional().describe("Restrict to module name (optional)"),
          max_results: z.number().optional().default(100).describe("Max matches to return")
        }),
        z.object({
          action: z.literal("string_at"),
          query: z.string().describe("Address of the string"),
          encoding: z.enum(['auto', 'ascii', 'unicode']).optional().default("auto"),
          max_length: z.number().optional().default(256).describe("Max bytes to read (max 4096)")
        }),
        z.object({
          action: z.literal("symbol_auto_complete"),
          query: z.string().describe("Partial symbol name prefix"),
          max_results: z.number().optional().default(20)
        }),
        z.object({
          action: z.literal("encode_type"),
          query: z.string().describe("Address to query"),
          size: z.string().optional().default("1")
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'pattern': {
            const body: Record<string, unknown> = {
              pattern: action.query,
              max_results: action.max_results,
              offset: action.offset,
            };
            if (action.address) body.address = action.address;
            if (action.size) body.size = action.size;
            if (action.limit !== undefined) body.limit = action.limit;
            data = await httpClient.post('/api/search/pattern', body);
            break;
          }
          case 'string':
            data = await httpClient.post('/api/search/string', {
              text: action.query,
              module: action.module,
              encoding: action.encoding,
              limit: action.limit,
              offset: action.offset,
            });
            break;
          case 'xor_scan': {
            const body: Record<string, unknown> = {
              text: action.query,
              max_results: action.max_results
            };
            if (action.module) body.module = action.module;
            data = await httpClient.post('/api/search/xor_scan', body);
            break;
          }
          case 'string_at':
            data = await httpClient.get('/api/search/string_at', {
              address: action.query,
              encoding: action.encoding,
              max_length: String(action.max_length),
            });
            break;
          case 'symbol_auto_complete':
            data = await httpClient.post('/api/search/auto_complete', {
              search: action.query,
              max_results: action.max_results,
            });
            break;
          case 'encode_type':
            data = await httpClient.get('/api/search/encode_type', { address: action.query, size: action.size });
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
