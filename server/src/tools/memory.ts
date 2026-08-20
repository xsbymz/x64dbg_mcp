import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryTools(server: McpServer) {
  server.tool(
    'x64dbg_memory',
    'Core memory operations: read, write, validate, allocate, free, protect, map, batch reads, pointer following, struct layout formatting, W^X/RWX security audit, injected code detection, and section comparison. ' +
    'Actions: read (read bytes), write (patch bytes), info (page info), is_valid (pointer check), is_code (code page check), ' +
    'allocate, free, protect, map (memory map), update_map, read_batch (multi-region read in one call), ' +
    'follow_pointers (dereference chain of offsets), ' +
    'struct_view (dynamically cast and format memory at an address using a field schema: byte, word, dword, qword, ptr, string), ' +
    'rwx_audit (scan entire virtual address space for W^X violations: RWX pages and unbacked executable allocations), ' +
    'injected_check (detect potential code injection/hollowing by comparing executable regions against module metadata), ' +
    'compare_sections (compare each memory section against its on-disk counterpart for a module).',
    {
      action: z.discriminatedUnion("action", [
        z.object({
          action: z.literal("read"),
          address: z.string().describe("Hex string or x64dbg expression (e.g. '0x401000', 'rsp', 'mod.entry(main)')"),
          size: z.string().optional().default("256").describe("Size in bytes (decimal or hex)")
        }),
        z.object({
          action: z.literal("write"),
          address: z.string().describe("Target address (hex or expression)"),
          bytes: z.string().describe("Hex bytes to write (e.g. '90 90' or 'CC')"),
          verify: z.boolean().optional().default(false).describe("Read back and verify write succeeded")
        }),
        z.object({ action: z.literal("info"), address: z.string().describe("Query page info for this address") }),
        z.object({ action: z.literal("is_valid"), address: z.string().describe("Check if address is a valid readable pointer") }),
        z.object({ action: z.literal("is_code"), address: z.string().describe("Check if address is in an executable page") }),
        z.object({ action: z.literal("rwx_audit") }),
        z.object({
          action: z.literal("struct_view"),
          address: z.string().describe("Base memory address of the struct instance"),
          fields: z.array(z.object({
            name: z.string().describe("Field name"),
            type: z.enum(['byte', 'word', 'dword', 'qword', 'ptr', 'string']).describe("Field data type"),
            offset: z.union([z.number(), z.string()]).optional().describe("Explicit byte offset (optional; otherwise auto-calculated)")
          })).describe("List of struct fields to parse and format")
        }),
        z.object({
          action: z.literal("allocate"),
          size: z.string().optional().default("0x1000").describe("Size in hex to allocate in the target process")
        }),
        z.object({
          action: z.literal("free"),
          address: z.string().describe("Address returned by a previous allocate call")
        }),
        z.object({
          action: z.literal("protect"),
          address: z.string(),
          size: z.string().optional().default("0x1000"),
          protection: z.string().describe("Page protection constant (e.g. 'PAGE_EXECUTE_READWRITE')")
        }),
        z.object({
          action: z.literal("map"),
          address: z.string().optional().describe("Return region info for a specific address, or full memory map if omitted")
        }),
        z.object({ action: z.literal("update_map") }),
        z.object({
          action: z.literal("read_batch"),
          regions: z.array(z.object({
            address: z.string().describe("Address of this region"),
            size: z.number().optional().default(256).describe("Size in bytes to read (max 10MB per region)")
          })).describe("List of memory regions to read (max 256 regions per call)")
        }),
        z.object({
          action: z.literal("follow_pointers"),
          address: z.string().describe("Starting address (hex or expression)"),
          offsets: z.array(z.union([z.number(), z.string()])).describe(
            "Sequence of offsets to add then dereference in order. " +
            "E.g. [0, 0x18, 0x10] reads ptr at (addr+0), then ptr at (that+0x18), then ptr at (that+0x10)."
          )
        }),
        z.object({ action: z.literal("injected_check") }),
        z.object({
          action: z.literal("compare_sections"),
          module: z.string().describe("Module name to compare against disk")
        })
      ])
    },
    async ({ action }) => {
      try {
        switch (action.action) {
          case 'read':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.get('/api/memory/read', { address: action.address, size: action.size }),
              null, 2) }] };
          case 'write':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/write', { address: action.address, bytes: action.bytes, verify: action.verify }),
              null, 2) }] };
          case 'info':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.get('/api/memory/page_info', { address: action.address }),
              null, 2) }] };
          case 'is_valid':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.get('/api/memory/is_valid', { address: action.address }),
              null, 2) }] };
          case 'is_code':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.get('/api/memory/is_code', { address: action.address }),
              null, 2) }] };
          case 'rwx_audit':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.get('/api/memory/rwx_audit'),
              null, 2) }] };
          case 'struct_view':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/struct_view', { address: action.address, fields: action.fields }),
              null, 2) }] };
          case 'allocate':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/allocate', { size: action.size }),
              null, 2) }] };
          case 'free':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/free', { address: action.address }),
              null, 2) }] };
          case 'protect':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/protect', { address: action.address, size: action.size, protection: action.protection }),
              null, 2) }] };
          case 'map':
            if (action.address) {
              return { content: [{ type: 'text', text: JSON.stringify(
                await httpClient.get('/api/memmap/at', { address: action.address }),
                null, 2) }] };
            } else {
              return { content: [{ type: 'text', text: JSON.stringify(
                await httpClient.get('/api/memmap/list'),
                null, 2) }] };
            }
          case 'update_map':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/update_map'),
              null, 2) }] };
          case 'read_batch':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/read_batch', { regions: action.regions }),
              null, 2) }] };
          case 'follow_pointers':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.post('/api/memory/follow_pointers', { address: action.address, offsets: action.offsets }),
              null, 2) }] };
          case 'injected_check':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.get('/api/memory/injected_check'),
              null, 2) }] };
          case 'compare_sections':
            return { content: [{ type: 'text', text: JSON.stringify(
              await httpClient.get('/api/memory/compare_sections', { module: action.module }),
              null, 2) }] };
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
