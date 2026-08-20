import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNtfsMftArtifactCarverTools(server: McpServer) {
  server.tool(
    'x64dbg_ntfs_mft_read_record',
    'Read NTFS Master File Table (MFT) volume metadata. Opens the volume directly to get MFT start LCN, bytes-per-cluster, bytes-per-MFT-record, and total record count. Returns attribute type reference table ($STANDARD_INFORMATION, $FILE_NAME, $DATA, $REPARSE_POINT, etc.).',
    {
      volume: z.string().optional().describe('Volume path (default: "\\\\\\\\.\\\\C:")'),
      record_number: z.number().optional().describe('MFT record number to read (default: 0 = $MFT itself)'),
    },
    async ({ volume, record_number }) => {
      const result = await httpClient.post('/api/ntfs_mft/read_record', {
        volume: volume ?? '\\\\.\\C:',
        record_number: record_number ?? 0,
      });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_ntfs_mft_detect_timestomp',
    'Detect NTFS timestamp manipulation (timestomping) for a file. Compares $STANDARD_INFORMATION (SI) timestamps — modifiable via SetFileTime() — against $FILE_NAME (FN) timestamps which are maintained by the NTFS kernel and harder to modify. Detects SI.Created > FN.Created, identical timestamps, and rounded nanosecond values.',
    {
      file_path: z.string().describe('Full file path to analyze for timestomping (e.g. "C:\\\\Windows\\\\temp\\\\malware.exe")'),
    },
    async ({ file_path }) => {
      const result = await httpClient.post('/api/ntfs_mft/detect_timestomp', { file_path });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_ntfs_mft_carve_deleted',
    'Get strategy and reference data for carving deleted NTFS MFT records. Returns MFT record size, deletion indicator (InUse bit = 0), magic signature, data recovery approach, and $UsnJrnl ($LogFile journal) path for file deletion event reconstruction even after MFT record reuse.',
    {},
    async () => {
      const result = await httpClient.post('/api/ntfs_mft/carve_deleted', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_ntfs_mft_enum_ads',
    'Enumerate NTFS Alternate Data Streams (ADS) on a file or directory. Detects non-default :$DATA streams used to hide payload data, configuration files, or executables. ADS can launch code via "wscript.exe file.txt:payload.js". Also detects Zone.Identifier download markers.',
    {
      directory: z.string().optional().describe('File or directory path to enumerate ADS (default: C:\\\\Windows\\\\Temp)'),
    },
    async ({ directory }) => {
      const result = await httpClient.post('/api/ntfs_mft/enum_ads', { directory: directory ?? 'C:\\Windows\\Temp' });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
