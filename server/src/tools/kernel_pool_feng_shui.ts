import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKernelPoolFengShuiTools(server: McpServer) {
  server.tool(
    'x64dbg_kernel_pool_scan_tags',
    'Scan kernel pool allocations via NtQuerySystemInformation(SystemBigPoolInformation) and SystemPoolTagInformation. Enumerates NonPagedPool and PagedPool chunks by tag name. Identifies allocation patterns for kernel objects: _EPROCESS ("Proc"), _TOKEN ("Toke"), _FILE_OBJECT ("File").',
    {
      tag_filter: z.string().optional().describe('Filter results to pool tags containing this string (e.g. "Proc", "Toke", "File")'),
    },
    async ({ tag_filter }) => {
      const result = await httpClient.post('/api/pool/scan_tags', { tag_filter: tag_filter ?? '' });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_kernel_pool_groom_layout',
    'Get kernel pool heap feng shui grooming strategy and reference data. Returns known kernel object sizes, pool types, recommended spray objects (IoCompletionReserve, Event, ThreadPool), and the 5-step pool overflow grooming methodology for exploit development.',
    {},
    async () => {
      const result = await httpClient.post('/api/pool/groom_layout', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_kernel_pool_detect_corruption',
    'Detect kernel pool corruption indicators via alloc/free mismatch analysis. Flags pool tags with anomalous allocation-free deltas (>1000 unfreed allocs = spray/leak, negative delta = double-free candidate). Critical for identifying pool overflow and use-after-free conditions.',
    {},
    async () => {
      const result = await httpClient.post('/api/pool/detect_corruption', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
