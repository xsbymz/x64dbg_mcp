import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPrefetchForensicsEngineTools(server: McpServer) {
  server.tool(
    'x64dbg_prefetch_list_executions',
    'List all Windows Prefetch files and parse execution metadata. Returns filenames, sizes, last-execution timestamps, path hashes, and automatic LOLBin detection (RUNDLL32, REGSVR32, MSHTA, WSCRIPT, CSCRIPT, POWERSHELL, CERTUTIL, BITSADMIN, MSIEXEC, WMIC, etc.). Critical for execution history reconstruction in incident response.',
    {},
    async () => {
      const result = await httpClient.post('/api/prefetch/list_executions', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_prefetch_parse_file',
    'Parse a specific Windows Prefetch SCCA file (v30 format for Windows 10/11). Returns version, exe name, path hash, and file size. Detects MAM (Xpress Huffman) compression used in Windows 10+ prefetch files and reports decompressed size. Decompression via RtlDecompressBufferEx is required for full content extraction.',
    {
      filename: z.string().describe('Prefetch filename from the Prefetch directory (e.g. "MALWARE.EXE-12345678.pf")'),
    },
    async ({ filename }) => {
      const result = await httpClient.post('/api/prefetch/parse_file', { filename });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_prefetch_detect_deletion_gaps',
    'Detect anti-forensic prefetch file deletion. Checks if prefetch is enabled (EnablePrefetcher registry value), identifies prefetcher mode (Application/Boot/Full), and returns gap detection methodology correlating with Windows Event Log 4688, $UsnJrnl, and Volume Shadow Copy for timeline reconstruction.',
    {},
    async () => {
      const result = await httpClient.post('/api/prefetch/detect_deletion_gaps', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_prefetch_export_timeline',
    'Export chronological execution timeline from all Windows Prefetch files. Returns all executables sorted by last-write timestamp with UTC datetime strings, file sizes, and execution ordering. Ideal for threat hunting, incident timeline reconstruction, and malware execution sequencing analysis.',
    {},
    async () => {
      const result = await httpClient.post('/api/prefetch/export_timeline', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
