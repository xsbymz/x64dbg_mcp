import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryForensicsAdvancedTools(server: McpServer) {
  server.tool('x64dbg_mf_analyze_compressed_pages', 'Analyze Windows 10+ memory compression: Mm, SMAP, compressed page store, page state transitions.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/analyze_compressed_pages', {}), null, 2) }] };
  });
  server.tool('x64dbg_mf_detect_hibernation_file', 'Detect and parse hibernation file (hiberfil.sys) for forensic memory extraction.', { hiberfil_path: z.string().describe('Path to hiberfil.sys') }, async ({ hiberfil_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/detect_hibernation_file', { hiberfil_path }), null, 2) }] };
  });
  server.tool('x64dbg_mf_analyze_page_file', 'Analyze page file (pagefile.sys) for deleted memory artifacts and forensic reconstruction.', { pagefile_path: z.string().describe('Path to pagefile.sys') }, async ({ pagefile_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/analyze_page_file', { pagefile_path }), null, 2) }] };
  });
  server.tool('x64dbg_mf_detect_hyperv_enlightenments', 'Detect Hyper-V enlightenments and synthetic interrupt controller (SynIC) state.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/detect_hyperv_enlightenments', {}), null, 2) }] };
  });
  server.tool('x64dbg_mf_analyze_wsl2_memory', 'Analyze WSL2 (Pico process) memory: LxCore.sys, VFS cache, Linux process memory mapping.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/analyze_wsl2_memory', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_mf_detect_transparent_hugepages', 'Detect Transparent Huge Pages (THP) usage and analyze THP-related attack surfaces.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/detect_transparent_hugepages', {}), null, 2) }] };
  });
  server.tool('x64dbg_mf_reconstruct_deleted_process', 'Reconstruct deleted process memory from page file and standby list.', { pid: z.number().describe('Target PID') }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/reconstruct_deleted_process', { pid }), null, 2) }] };
  });
  server.tool('x64dbg_mf_analyze_kernel_stacks', 'Analyze kernel stacks for all threads: stack frame reconstruction, kernel module attribution.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/analyze_kernel_stacks', {}), null, 2) }] };
  });
  server.tool('x64dbg_mf_detect_memory_tampering', 'Detect memory tampering: COW breaking, copy-on-write violations, shared section manipulation.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/detect_memory_tampering', {}), null, 2) }] };
  });
  server.tool('x64dbg_mf_analyze_standby_list', 'Analyze standby list and modified page list for forensic memory reconstruction.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/analyze_standby_list', {}), null, 2) }] };
  });
  server.tool('x64dbg_mf_detect_memory_injection', 'Detect memory injection techniques: Process Hollowing, Process Doppelganging, APC injection.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/detect_memory_injection', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_mf_correlate_artifacts', 'Correlate memory artifacts across processes: handle inheritance, shared sections, IPC channels.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/mem_forensics/correlate_artifacts', {}), null, 2) }] };
  });
}
