import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKernelStructuresTools(server: McpServer) {
  // KTHREAD / ETHREAD
  server.tool('x64dbg_kthread_walk_all_threads', 'Walk all kernel _KTHREAD / _ETHREAD objects for a process.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kthread/walk_all_threads', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_kthread_dump_fields', 'Dump fields of a specific ETHREAD object.', { tid: z.number().optional() }, async ({ tid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kthread/dump_thread_fields', { tid: tid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_kthread_detect_apc_anomalies', 'Detect stealth unlinked APCs and Special User APC anomalies.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kthread/detect_apc_anomalies', {}), null, 2) }] };
  });

  // KPCR / KPRCB
  server.tool('x64dbg_kpcr_dump_all_cpus', 'Inspect per-CPU Kernel Processor Control Region (KPCR) state.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kpcr/dump_all_cpus', {}), null, 2) }] };
  });
  server.tool('x64dbg_kpcr_read_prcb_fields', 'Read Processor Control Block (KPRCB) fields (CurrentThread, DpcList).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kpcr/read_prcb_fields', {}), null, 2) }] };
  });
  server.tool('x64dbg_kpcr_detect_dpc_anomalies', 'Detect Deferred Procedure Call (DPC) hijacking.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kpcr/detect_dpc_anomalies', {}), null, 2) }] };
  });

  // Object Types
  server.tool('x64dbg_obj_type_enumerate_types', 'Enumerate Object Manager kernel object types.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/obj_type/enumerate_types', {}), null, 2) }] };
  });
  server.tool('x64dbg_obj_type_dump_procedures', 'Dump Object Manager Type Initializer procedure pointers.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/obj_type/dump_type_procedures', {}), null, 2) }] };
  });
  server.tool('x64dbg_obj_type_detect_hooked_procedures', 'Detect Object Manager Type Procedure pointer hooks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/obj_type/detect_hooked_procedures', {}), null, 2) }] };
  });

  // DKOM Detector
  server.tool('x64dbg_dkom_detect_hidden_processes', 'Detect DKOM-hidden processes unlinked from ActiveProcessLinks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dkom/detect_hidden_processes', {}), null, 2) }] };
  });
  server.tool('x64dbg_dkom_compare_pspcid_vs_activelist', 'Compare PspCidTable vs ActiveProcessLinks to discover hidden processes.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dkom/compare_pspcid_vs_activelist', {}), null, 2) }] };
  });
  server.tool('x64dbg_dkom_find_unlinked_eprocess', 'Scan for unlinked EPROCESS structures via network socket ownership.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dkom/find_unlinked_eprocess', {}), null, 2) }] };
  });

  // Driver Objects & MajorFunction
  server.tool('x64dbg_driver_obj_enumerate_all', 'Enumerate kernel \\Driver objects and inspect dispatch tables.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/driver_obj/enumerate_all', {}), null, 2) }] };
  });
  server.tool('x64dbg_driver_obj_dump_major_functions', 'Dump MajorFunction[28] dispatch function pointer array.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/driver_obj/dump_major_function_table', {}), null, 2) }] };
  });
  server.tool('x64dbg_driver_obj_detect_dispatch_hooks', 'Detect MajorFunction[28] inline hooks and redirection.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/driver_obj/detect_dispatch_hooks', {}), null, 2) }] };
  });

  // IRP Inspector
  server.tool('x64dbg_irp_list_pending', 'Inspect I/O Request Packet (IRP) structures and pending status.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/irp/list_pending', {}), null, 2) }] };
  });
  server.tool('x64dbg_irp_decode_stack_locations', 'Decode IO_STACK_LOCATION parameters across driver layers.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/irp/decode_stack_locations', {}), null, 2) }] };
  });
  server.tool('x64dbg_irp_detect_suspicious_completion', 'Detect unbacked CompletionRoutine pointers in IRP stacks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/irp/detect_suspicious_completion_routines', {}), null, 2) }] };
  });

  // Win32k Shadow SSDT
  server.tool('x64dbg_shadow_ssdt_dump_table', 'Dump Win32k Shadow System Service Descriptor Table.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/shadow_ssdt/dump_table', {}), null, 2) }] };
  });
  server.tool('x64dbg_shadow_ssdt_validate_entries', 'Validate Shadow SSDT function entries against win32k modules.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/shadow_ssdt/validate_entries', {}), null, 2) }] };
  });
  server.tool('x64dbg_shadow_ssdt_detect_hooks', 'Detect Shadow SSDT table pointer swaps and inline GUI hooks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/shadow_ssdt/detect_hooks', {}), null, 2) }] };
  });
}
