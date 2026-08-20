import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWow64CrossBitnessMemoryReaderTools(server: McpServer) {
  server.tool(
    'x64dbg_wow64_cross_bitness_memory_reader',
    'Read and inspect full 64-bit address space memory (NtWow64ReadVirtualMemory64, 64-bit TEB, 64-bit PEB, 64-bit ntdll) directly from a 32-bit WOW64 target.',
    {
      action: z.enum(['read_64bit_memory', 'get_64bit_peb_address', 'get_64bit_teb_address']).describe('WOW64 memory action'),
      address64: z.string().optional().describe('64-bit virtual memory address string (e.g. 0x00007FFE12340000)'),
      size: z.number().optional().describe('Number of bytes to read (default 64)'),
    },
    async ({ action, address64, size }) => {
      let data: unknown;
      switch (action) {
        case 'read_64bit_memory':
          data = await httpClient.post('/api/wow64_mem/read64', { address64, size });
          break;
        case 'get_64bit_peb_address':
          data = await httpClient.get('/api/wow64_mem/peb64');
          break;
        case 'get_64bit_teb_address':
          data = await httpClient.get('/api/wow64_mem/teb64');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
