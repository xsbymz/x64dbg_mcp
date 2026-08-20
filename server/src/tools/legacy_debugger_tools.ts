import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerLegacyDebuggerTools(server: McpServer) {
  // Debug control
  server.tool('x64dbg_debug_force_pause', 'Force immediate pause of the debuggee process.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/force_pause', {}), null, 2) }] };
  });
  server.tool('x64dbg_debug_pause', 'Pause debuggee execution at the next instruction boundary.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/pause', {}), null, 2) }] };
  });
  server.tool('x64dbg_debug_restart', 'Restart the target debuggee process.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/restart', {}), null, 2) }] };
  });
  server.tool('x64dbg_debug_run', 'Resume target execution (continue).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/run', {}), null, 2) }] };
  });
  server.tool('x64dbg_debug_run_to', 'Run target execution until specified address is hit.', { address: z.string().describe('Target address hex') }, async ({ address }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/run_to', { address }), null, 2) }] };
  });
  server.tool('x64dbg_debug_step_into', 'Single-step into the next instruction.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/step_into', {}), null, 2) }] };
  });
  server.tool('x64dbg_debug_step_out', 'Execute until current function returns (step out).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/step_out', {}), null, 2) }] };
  });
  server.tool('x64dbg_debug_step_over', 'Single-step over calls and loops.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/step_over', {}), null, 2) }] };
  });
  server.tool('x64dbg_debug_stop', 'Terminate and stop target debugging session.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/debug/stop', {}), null, 2) }] };
  });

  // Breakpoints
  server.tool('x64dbg_bp_configure', 'Configure breakpoint properties (passCount, silent, fastResume).', { address: z.string().describe('Breakpoint address hex') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/configure', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_configure_batch', 'Batch configure multiple breakpoints.', { breakpoints: z.array(z.record(z.any())).describe('List of breakpoint configs') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/configure_batch', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_delete', 'Delete breakpoint at specified address.', { address: z.string().describe('Address hex') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/delete', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_disable', 'Disable breakpoint without deletion.', { address: z.string().describe('Address hex') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/disable', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_enable', 'Enable a disabled breakpoint.', { address: z.string().describe('Address hex') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/enable', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_reset_hit_count', 'Reset hit counter on a breakpoint.', { address: z.string().describe('Address hex') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/reset_hit_count', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_set', 'Set standard software INT3 breakpoint.', { address: z.string().describe('Address hex') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/set', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_set_condition', 'Set hit condition expression on breakpoint.', { address: z.string().describe('Address hex'), condition: z.string().describe('Condition expression') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/set_condition', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_set_hardware', 'Set hardware breakpoint (DR0-DR3).', { address: z.string().describe('Address hex'), type: z.string().optional().describe('Type: execute, read, write') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/set_hardware', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_set_log', 'Set log message on breakpoint hit.', { address: z.string().describe('Address hex'), message: z.string().describe('Log format string') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/set_log', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_set_memory', 'Set memory page access/write breakpoint.', { address: z.string().describe('Address hex'), size: z.number().optional() }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/set_memory', data), null, 2) }] };
  });
  server.tool('x64dbg_bp_toggle', 'Toggle breakpoint enabled/disabled state.', { address: z.string().describe('Address hex') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/breakpoints/toggle', data), null, 2) }] };
  });

  // Threads
  server.tool('x64dbg_threads_name', 'Set or get thread debug name.', { tid: z.number().describe('Thread ID'), name: z.string().optional() }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/threads/name', data), null, 2) }] };
  });
  server.tool('x64dbg_threads_resume', 'Resume execution of suspended thread.', { tid: z.number().describe('Thread ID') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/threads/resume', data), null, 2) }] };
  });
  server.tool('x64dbg_threads_suspend', 'Suspend execution of target thread.', { tid: z.number().describe('Thread ID') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/threads/suspend', data), null, 2) }] };
  });
  server.tool('x64dbg_threads_switch', 'Switch debugger context to specific thread.', { tid: z.number().describe('Thread ID') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/threads/switch', data), null, 2) }] };
  });
  server.tool('x64dbg_threads_teb', 'Inspect Thread Environment Block (TEB) for thread.', { tid: z.number().describe('Thread ID') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/threads/teb', data), null, 2) }] };
  });

  // Commands
  server.tool('x64dbg_command_batch', 'Execute a batch list of x64dbg commands.', { commands: z.array(z.string()).describe('List of commands') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/command/batch', data), null, 2) }] };
  });
  server.tool('x64dbg_command_db_hash', 'Compute hash of current symbol and comment database.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/command/db_hash', {}), null, 2) }] };
  });
  server.tool('x64dbg_command_execute_silent', 'Execute x64dbg command without logging to GUI log window.', { command: z.string().describe('x64dbg command string') }, async (data) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/command/execute_silent', data), null, 2) }] };
  });
  server.tool('x64dbg_command_history', 'Retrieve recent x64dbg command execution history.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/command/history', {}), null, 2) }] };
  });

  // Anti-Debug
  server.tool('x64dbg_antidebug_exception_handlers', 'Analyze anti-debug checks using SEH/VEH exception tricks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/antidebug/exception_handlers', {}), null, 2) }] };
  });
  server.tool('x64dbg_antidebug_hardware_bp_detection', 'Detect hardware breakpoint (DR0-DR7) detection tricks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/antidebug/hardware_bp_detection', {}), null, 2) }] };
  });
  server.tool('x64dbg_antidebug_ntquery_hooks', 'Check for NtQueryInformationProcess / NtSetInformationThread anti-debug hooks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/antidebug/ntquery_hooks', {}), null, 2) }] };
  });
  server.tool('x64dbg_antidebug_timing_checks', 'Inspect RDTSC / QueryPerformanceCounter anti-debug timing tricks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/antidebug/timing_checks', {}), null, 2) }] };
  });

  // Exploit Primitives
  server.tool('x64dbg_primitives_arbitrary_read', 'Model arbitrary read exploit primitive candidates in target memory.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/primitives/arbitrary_read', {}), null, 2) }] };
  });
  server.tool('x64dbg_primitives_arbitrary_write', 'Model arbitrary write / write-what-where exploit primitives.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/primitives/arbitrary_write', {}), null, 2) }] };
  });
  server.tool('x64dbg_primitives_info_leak', 'Identify information leak / ASLR bypass primitives.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/primitives/info_leak', {}), null, 2) }] };
  });
  server.tool('x64dbg_primitives_stack_pivot', 'Identify stack pivot gadget primitives (XCHG ESP, EAX / MOV RSP, RDX).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/primitives/stack_pivot', {}), null, 2) }] };
  });

  // CFG
  server.tool('x64dbg_cfg_branch_analysis', 'Perform Control Flow Guard branch analysis.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cfg/branch_analysis', {}), null, 2) }] };
  });
  server.tool('x64dbg_cfg_flattening', 'Detect Control Flow Flattening (CFF) dispatcher loops.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cfg/flattening', {}), null, 2) }] };
  });

  // Obfuscation & VM
  server.tool('x64dbg_obfuscation_detect', 'Detect general binary obfuscation techniques (MBA, opaque predicates).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/obfuscation/detect', {}), null, 2) }] };
  });
  server.tool('x64dbg_obfuscation_opaque_predicates', 'Detect dead code branches and opaque predicates.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/obfuscation/opaque_predicates', {}), null, 2) }] };
  });
  server.tool('x64dbg_obfuscation_string_decrypt', 'Auto-identify and decrypt obfuscated strings.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/obfuscation/string_decrypt', {}), null, 2) }] };
  });
  server.tool('x64dbg_obfuscation_vm_detect', 'Detect VMProtect / Themida bytecode interpreter dispatch loops.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/obfuscation/vm_detect', {}), null, 2) }] };
  });

  // VM Detection
  server.tool('x64dbg_vm_cpuid_check', 'Check CPUID hypervisor bit and brand signatures.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vm/cpuid_check', {}), null, 2) }] };
  });
  server.tool('x64dbg_vm_detect', 'Detect VirtualBox, VMware, QEMU, Hyper-V, and KVM presence.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vm/detect', {}), null, 2) }] };
  });
  server.tool('x64dbg_vm_driver_check', 'Check for VM hardware device driver artifacts (VBoxGuest, vmmouse).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vm/driver_check', {}), null, 2) }] };
  });
  server.tool('x64dbg_vm_registry_artifacts', 'Scan registry for virtualization system artifacts.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/vm/registry_artifacts', {}), null, 2) }] };
  });

  // Kernel & Hashes
  server.tool('x64dbg_kernel_callbacks', 'Enumerate kernel driver callbacks (PsSetCreateProcessNotifyRoutine, etc.).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kernel/callbacks', {}), null, 2) }] };
  });
  server.tool('x64dbg_kernel_pool_overflow_detection', 'Inspect kernel pool chunks for overflow indicators.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kernel/pool_overflow_detection', {}), null, 2) }] };
  });
  server.tool('x64dbg_kernel_token_steal_check', 'Check for token stealing privilege escalation (SYSTEM token swap).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/kernel/token_steal_check', {}), null, 2) }] };
  });
  server.tool('x64dbg_iathash', 'Calculate IAT Hash (imphash) for PE import analysis.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/iathash', {}), null, 2) }] };
  });
  server.tool('x64dbg_eathash', 'Calculate Export Address Table Hash (eathash) for export fingerprinting.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/eathash', {}), null, 2) }] };
  });
}
