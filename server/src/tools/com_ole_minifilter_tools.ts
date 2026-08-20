import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComOleMinifilterTools(server: McpServer) {
  // IDispatch Invoke Tracer
  server.tool('x64dbg_idispatch_trace_invoke', 'Trace IDispatch::Invoke automation calls.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/idispatch/hook_invoke_trace', {}), null, 2) }] };
  });
  server.tool('x64dbg_idispatch_enumerate_dispids', 'Enumerate automation DISPIDs for script host objects.', { prog_id: z.string().optional() }, async ({ prog_id }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/idispatch/enumerate_dispids', { prog_id: prog_id ?? 'WScript.Shell' }), null, 2) }] };
  });
  server.tool('x64dbg_idispatch_detect_suspicious_auto', 'Detect suspicious COM automation patterns in Office processes.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/idispatch/detect_suspicious_automation', {}), null, 2) }] };
  });

  // Moniker Activation
  server.tool('x64dbg_moniker_audit_activations', 'Audit COM Moniker activations (script:, clsid:, new:, file:).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/moniker/trace_activations', {}), null, 2) }] };
  });
  server.tool('x64dbg_moniker_decode_display_names', 'Decode moniker display name strings and URL parameters.', { display_name: z.string().describe('Display name') }, async ({ display_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/moniker/decode_display_names', { display_name }), null, 2) }] };
  });
  server.tool('x64dbg_moniker_detect_fileless', 'Detect fileless scriptlet moniker execution attacks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/moniker/detect_fileless_activation', {}), null, 2) }] };
  });

  // DCOM Lateral Movement
  server.tool('x64dbg_dcom_detect_lateral_movement', 'Detect remote DCOM object activations (MMC20, ShellWindows).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dcom/enumerate_remote_activations', {}), null, 2) }] };
  });
  server.tool('x64dbg_dcom_detect_known_clsids', 'Detect known lateral movement DCOM CLSIDs.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dcom/detect_known_lm_clsids', {}), null, 2) }] };
  });
  server.tool('x64dbg_dcom_trace_coserverinfo', 'Trace COSERVERINFO remote connections and credentials.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dcom/trace_coserverinfo_connections', {}), null, 2) }] };
  });

  // OLE Structured Storage
  server.tool('x64dbg_ole_storage_parse', 'Parse OLE Compound File Binary streams.', { file_path: z.string().describe('File path') }, async ({ file_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ole_storage/parse_compound_file', { file_path }), null, 2) }] };
  });
  server.tool('x64dbg_ole_storage_enumerate_streams', 'Enumerate CFB streams (SummaryInformation, WordDocument, VBA).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ole_storage/enumerate_streams', {}), null, 2) }] };
  });
  server.tool('x64dbg_ole_storage_detect_exploits', 'Detect Equation Editor exploits and VBA purging patterns.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ole_storage/detect_exploit_patterns', {}), null, 2) }] };
  });

  // Minifilter Drivers
  server.tool('x64dbg_minifilter_audit', 'Enumerate filesystem Minifilter drivers and altitude hierarchy.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/minifilter/enumerate_filters', {}), null, 2) }] };
  });
  server.tool('x64dbg_minifilter_check_altitudes', 'Audit minifilter altitude ordering relative to Anti-Virus filters.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/minifilter/check_altitude_ordering', {}), null, 2) }] };
  });
  server.tool('x64dbg_minifilter_validate_callbacks', 'Validate FLT_OPERATION_REGISTRATION callback pointers.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/minifilter/validate_callback_pointers', {}), null, 2) }] };
  });

  // Volume Shadow Copies (VSS)
  server.tool('x64dbg_vss_audit_shadows', 'Enumerate Volume Shadow Copies.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vss/enumerate_snapshots', {}), null, 2) }] };
  });
  server.tool('x64dbg_vss_detect_deletion', 'Detect ransomware shadow deletion commands (vssadmin/wmic/IOCTL).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vss/detect_deletion_attempts', {}), null, 2) }] };
  });
  server.tool('x64dbg_vss_read_previous_version', 'Mount volume shadow copy to recover pre-ransomware versions.', { file_path: z.string().describe('File path') }, async ({ file_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vss/mount_and_read_previous_version', { file_path }), null, 2) }] };
  });

  // Windows Event Log (EVTX)
  server.tool('x64dbg_evtx_parse_log', 'Parse Windows EVTX binary log header and chunk structures.', { log_path: z.string().optional() }, async ({ log_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/evtx/parse_log_file', { log_path: log_path ?? 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx' }), null, 2) }] };
  });
  server.tool('x64dbg_evtx_detect_gaps', 'Detect sequence number gaps indicating audit record deletion.', { log_path: z.string().optional() }, async ({ log_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/evtx/detect_sequence_gaps', { log_path: log_path ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_evtx_find_clearing_events', 'Find audit clearing event IDs (1102, 104, 1100, 7034).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/evtx/find_clearing_events', {}), null, 2) }] };
  });
}
