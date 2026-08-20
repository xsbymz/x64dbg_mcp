import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMmvadTreeExplorerTools(server: McpServer) {
  server.tool(
    'x64dbg_mmvad_tree_explorer_walk',
    'Walk the _MMVAD Virtual Address Descriptor Red-Black tree for a process. Reveals all virtual memory regions including hidden allocations missed by standard VirtualQueryEx enumeration. Detects AWE mappings, reflective injection, and VadWriteWatch regions used by packers.',
    {
      pid: z.number().optional().describe('Target process ID (0 = current process)'),
    },
    async ({ pid }) => {
      const result = await httpClient.post('/api/mmvad/walk_tree', { pid: pid ?? 0 });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_mmvad_find_hidden_regions',
    'Detect hidden and anomalous memory regions in a process VAD tree. Identifies executable private memory (injected shellcode), large private commits (heap spray / AWE regions), and private RWX allocations that may indicate code injection or memory-resident malware.',
    {},
    async () => {
      const result = await httpClient.post('/api/mmvad/find_hidden_regions', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_mmvad_dump_vad_node',
    'Dump detailed _MMVAD node information for a specific memory base address. Returns allocation base, region size, protection flags, type (MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE), and allocation protection for forensic analysis.',
    {
      base: z.string().describe('Base address of the VAD node to dump (hex string, e.g. "0x7FF000000000")'),
    },
    async ({ base }) => {
      const result = await httpClient.post('/api/mmvad/dump_vad_node', { base: parseInt(base, 16) });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
