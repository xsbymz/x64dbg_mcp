import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessInjectionEvasionDetectorTools(server: McpServer) {
  server.tool('x64dbg_injection_detect_herpaderping', 'Detect Process Herpaderping via SEC_IMAGE backing file mismatch (Sysmon Event 25 pattern).', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_herpaderping', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_ghosting', 'Detect Process Ghosting via deleted backing file and SEC_IMAGE_NO_EXECUTE section.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_ghosting', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_preluding', 'Detect Process Preluding via legacy NtCreateProcess/NtCreateProcessEx syscall usage before process creation callbacks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_preluding', {}), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_io_ring_exploit', 'Detect I/O Ring (IORING_OBJECT) buffer table corruption primitives (CVE-2025-21333, CVE-2024-38193).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_io_ring_exploit', {}), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_wnf_manipulation', 'Detect WNF state data manipulation used for pool corruption and I/O Ring primitive setup.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_wnf_manipulation', {}), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_early_apc', 'Detect Early APC injection before process creation callbacks fire (Process Preluding variant).', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_early_apc', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_process_doppelganging', 'Detect Process Doppelganging via transacted file operations and TxF junction points.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_process_doppelganging', {}), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_ghostly_hollowing', 'Detect Ghostly Hollowing hybrid technique combining Process Hollowing with section cache exploitation.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_ghostly_hollowing', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_injection_analyze_legacy_createprocess', 'Analyze all processes created via legacy NtCreateProcess/NtCreateProcessEx vs modern NtCreateUserProcess.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/analyze_legacy_createprocess', {}), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_thread_hijack_early', 'Detect thread hijacking before thread creation callbacks via QueueUserAPC on alertable threads.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_thread_hijack_early', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_injection_map_etw_threat_intel', 'Map Microsoft-Windows-Threat-Intelligence ETW provider events for process injection detection coverage.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/map_etw_threat_intel', {}), null, 2) }] };
  });
  server.tool('x64dbg_injection_detect_ect_abuse', 'Detect Exception Continuable Trap (ECT) abuse for code execution without traditional injection.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/injection_evasion/detect_ect_abuse', {}), null, 2) }] };
  });
}
