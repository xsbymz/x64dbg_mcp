import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAnalysisTools(server: McpServer) {
  server.tool(
    'x64dbg_analysis',
    'Get function info, cross-references, basic blocks, source location, Shannon entropy, ROP/JOP gadgets, C++ VTables, backward register data-flow dependencies, ROP chain builder, and VTable+RTTI reconstruction. ' +
    'Actions: function (function bounds, name, size at address), ' +
    'xrefs_to (who calls/jumps to this address), ' +
    'xrefs_from (what this address calls/jumps to), ' +
    'basic_blocks (CFG basic blocks within function), ' +
    'source (source file/line info), ' +
    'mnemonic_brief (description of a mnemonic like "mov", "push"), ' +
    'entropy (calculate Shannon entropy 0.0-8.0), ' +
    'rop_gadgets (scan for ROP gadgets with filter), ' +
    'rop_gadgets_advanced (enhanced gadget scanner with quality scoring), ' +
    'rop_chain_builder (find gadgets matching a target effect for chain building), ' +
    'vtable (inspect C++ VTable to enumerate virtual method slots), ' +
    'vtable_rtti (extended VTable inspection with RTTI Complete Object Locator detection), ' +
    'dataflow (trace backward from address/CIP to identify register provenance).',
    {
      action: z.enum(['function', 'xrefs_to', 'xrefs_from', 'basic_blocks', 'source', 'mnemonic_brief', 'entropy', 'rop_gadgets', 'rop_gadgets_advanced', 'rop_chain_builder', 'vtable', 'vtable_rtti', 'dataflow']).describe(
        'Type of analysis: function|xrefs_to|xrefs_from|basic_blocks|source|mnemonic_brief|entropy|rop_gadgets|rop_gadgets_advanced|rop_chain_builder|vtable|vtable_rtti|dataflow'
      ),
      query: z.string().optional().default('cip').describe('Address/symbol to look up, module name for entropy/rop_gadgets, or target address for vtable/dataflow'),
      size: z.string().optional().describe('Byte size when calculating entropy for an address (optional)'),
      register: z.string().optional().default('rax').describe('Target register for dataflow action (e.g. "rax", "rcx", "rsp", "rbx")'),
      depth: z.number().optional().default(15).describe('Lookback depth in instructions for dataflow action (default 15)'),
      filter: z.enum(['all', 'pop', 'pivot', 'xchg', 'mov', 'syscall']).optional().default('all').describe('Filter category for rop_gadgets action'),
      max_results: z.number().optional().default(100).describe('Max results to return (for rop_gadgets or vtable)'),
      min_quality: z.number().optional().default(0).describe('Minimum quality score for rop_gadgets_advanced'),
      target_effect: z.string().optional().describe('Target effect pattern for rop_chain_builder (e.g. "pop rcx; ret")')
    },
    async ({ action, query, size, register, depth, filter, max_results, min_quality, target_effect }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'function':      data = await httpClient.get('/api/analysis/function',      { address: query }); break;
          case 'xrefs_to':     data = await httpClient.get('/api/analysis/xrefs_to',     { address: query }); break;
          case 'xrefs_from':   data = await httpClient.get('/api/analysis/xrefs_from',   { address: query }); break;
          case 'basic_blocks': data = await httpClient.get('/api/analysis/basic_blocks',  { address: query }); break;
          case 'source':       data = await httpClient.get('/api/analysis/source',        { address: query }); break;
          case 'mnemonic_brief': data = await httpClient.get('/api/analysis/mnemonic_brief', { mnemonic: query }); break;
          case 'entropy': {
            if (query.includes('.') || query.endsWith('.exe') || query.endsWith('.dll')) {
              data = await httpClient.get('/api/analysis/entropy', { module: query });
            } else {
              data = await httpClient.get('/api/analysis/entropy', { address: query, size: size ?? '0x1000' });
            }
            break;
          }
          case 'rop_gadgets': {
            const params: Record<string, string> = { filter, max_results: String(max_results) };
            if (query && query !== 'cip') params.module = query;
            data = await httpClient.get('/api/analysis/rop_gadgets', params);
            break;
          }
          case 'rop_gadgets_advanced': {
            const params: Record<string, string> = { filter, min_quality: String(min_quality ?? 0) };
            if (query && query !== 'cip') params.module = query;
            data = await httpClient.get('/api/analysis/rop_gadgets_advanced', params);
            break;
          }
          case 'rop_chain_builder': {
            const params: Record<string, string> = {};
            if (query && query !== 'cip') params.module = query;
            if (target_effect) params.target_effect = target_effect;
            data = await httpClient.get('/api/analysis/rop_chain_builder', params);
            break;
          }
          case 'vtable':
            data = await httpClient.get('/api/analysis/vtable', { address: query, max_methods: String(max_results) });
            break;
          case 'vtable_rtti':
            data = await httpClient.get('/api/analysis/vtable_rtti', { address: query });
            break;
          case 'dataflow':
            data = await httpClient.get('/api/analysis/dataflow', { address: query, register: register ?? 'rax', depth: String(depth) });
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );

  server.tool(
    'x64dbg_database',
    'List known constants, error codes, defined structs, or search for strings in a module. ' +
    'The "strings" action supports limit/offset pagination to avoid huge context-blowing responses. ' +
    'Actions: constants, error_codes, structs, strings.',
    {
      action: z.enum(['constants', 'error_codes', 'structs', 'strings']).describe('Type of list to retrieve'),
      module: z.string().optional().describe('Module name (required for strings action)'),
      limit: z.number().optional().default(200).describe('Max strings to return (pagination, strings action only)'),
      offset: z.number().optional().default(0).describe('Skip first N strings (pagination, strings action only)')
    },
    async ({ action, module, limit, offset }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'constants':   data = await httpClient.get('/api/analysis/constants'); break;
          case 'error_codes': data = await httpClient.get('/api/analysis/error_codes'); break;
          case 'structs':     data = await httpClient.get('/api/analysis/structs'); break;
          case 'strings':
            if (!module) throw new Error("module is required for strings action");
            data = await httpClient.get('/api/analysis/strings', {
              module,
              limit:  String(limit ?? 200),
              offset: String(offset ?? 0),
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

  server.tool(
    'x64dbg_address_convert',
    'Convert between Virtual Address (VA) and File Offset. ' +
    'va_to_file: give a VA, get the raw file offset. ' +
    'file_to_va: give a module name + file offset, get the loaded VA.',
    {
      action: z.enum(['va_to_file', 'file_to_va']).describe('va_to_file or file_to_va'),
      address: z.string().optional().describe('Virtual address in hex (required for va_to_file)'),
      module: z.string().optional().describe('Module name (required for file_to_va)'),
      offset: z.string().optional().describe('File offset in hex (required for file_to_va)')
    },
    async ({ action, address, module, offset }) => {
      try {
        let data: unknown;
        if (action === 'va_to_file') {
          if (!address) throw new Error("address is required for va_to_file");
          data = await httpClient.get('/api/analysis/va_to_file', { address });
        } else {
          if (!module || !offset) throw new Error("module and offset required for file_to_va");
          data = await httpClient.get('/api/analysis/file_to_va', { module, offset });
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );

  server.tool(
    'x64dbg_watchdog',
    'Check if a watch expression watchdog has been triggered. Useful for polling whether a condition has been met.',
    {
      id: z.string().optional().default('0').describe('Watch ID (decimal)'),
    },
    async ({ id }) => {
      try {
        const data = await httpClient.get('/api/analysis/watch', { id });
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
