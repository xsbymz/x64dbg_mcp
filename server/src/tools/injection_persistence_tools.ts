import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInjectionPersistenceTools(server: McpServer) {
  // DLL Notification
  server.tool('x64dbg_dll_notify_enumerate_callbacks', 'Enumerate LdrRegisterDllNotification callbacks in ntdll!LdrpDllNotificationList.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dll_notify/enumerate_callbacks', {}), null, 2) }] };
  });
  server.tool('x64dbg_dll_notify_validate_pointers', 'Validate DLL notification callback pointers against loaded modules.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dll_notify/validate_callback_pointers', {}), null, 2) }] };
  });
  server.tool('x64dbg_dll_notify_detect_malicious', 'Detect unauthorized DLL load notification callbacks (Turla/APT28).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/dll_notify/detect_malicious_registrations', {}), null, 2) }] };
  });

  // Shim Database (SDB)
  server.tool('x64dbg_shim_enumerate_installed', 'Enumerate installed Application Compatibility Shim Databases.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/shim/enumerate_installed_databases', {}), null, 2) }] };
  });
  server.tool('x64dbg_shim_parse_sdb', 'Parse raw .sdb shim database tags and matching executable entries.', { path: z.string().optional() }, async ({ path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/shim/parse_sdb_file', { path: path ?? 'C:\\Windows\\AppPatch\\sysmain.sdb' }), null, 2) }] };
  });
  server.tool('x64dbg_shim_detect_malicious', 'Detect malicious Application Shims (InjectDLL, RedirectEXE, DisableASLR).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/shim/detect_malicious_shims', {}), null, 2) }] };
  });

  // COM Hijacking
  server.tool('x64dbg_com_hijack_scan_overrides', 'Scan HKCU\\Software\\Classes\\CLSID for user-mode COM hijacking overrides.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/com_hijack/scan_hkcu_overrides', {}), null, 2) }] };
  });
  server.tool('x64dbg_com_hijack_detect_substitutions', 'Detect InprocServer32 DLL path substitutions in HKCU vs HKCR.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/com_hijack/detect_dll_substitutions', {}), null, 2) }] };
  });
  server.tool('x64dbg_com_hijack_compare_hkcu_hkcr', 'Compare complete HKCU vs HKCR COM registration diff.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/com_hijack/compare_hkcu_vs_hkcr', {}), null, 2) }] };
  });

  // WMI Subscriptions
  server.tool('x64dbg_wmi_sub_enumerate', 'Enumerate WMI Event Subscriptions (__EventFilter, ActiveScriptEventConsumer).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/wmi_sub/enumerate_subscriptions', {}), null, 2) }] };
  });
  server.tool('x64dbg_wmi_sub_decode_scripts', 'Extract ActiveScriptEventConsumer VBScript/JScript payload text.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/wmi_sub/decode_active_script_consumers', {}), null, 2) }] };
  });
  server.tool('x64dbg_wmi_sub_detect_bindings', 'Detect suspicious __FilterToConsumerBinding linkages in WMI repository.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/wmi_sub/detect_suspicious_bindings', {}), null, 2) }] };
  });

  // Scheduled Tasks
  server.tool('x64dbg_sched_task_enumerate', 'Enumerate Scheduled Tasks from %WINDIR%\\System32\\Tasks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sched_task/enumerate_all', {}), null, 2) }] };
  });
  server.tool('x64dbg_sched_task_parse_xml', 'Parse task XML registration info, triggers, and actions.', { task_name: z.string().describe('Task name') }, async ({ task_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sched_task/parse_task_xml', { task_name }), null, 2) }] };
  });
  server.tool('x64dbg_sched_task_detect_suspicious', 'Detect hidden tasks, LOLBin actions, and missing Security Descriptors.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/sched_task/detect_suspicious_tasks', {}), null, 2) }] };
  });

  // AppInit DLLs
  server.tool('x64dbg_appinit_read_configured', 'Read configured AppInit_DLLs registry values.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/appinit/read_configured_dlls', {}), null, 2) }] };
  });
  server.tool('x64dbg_appinit_verify_signatures', 'Verify Authenticode signatures of AppInit DLLs.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/appinit/verify_dll_signatures', {}), null, 2) }] };
  });
  server.tool('x64dbg_appinit_assess_state', 'Assess AppInit_DLLs system injection state and Secure Boot enforcement.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/appinit/assess_load_state', {}), null, 2) }] };
  });

  // Gargoyle / Ekko Sleep
  server.tool('x64dbg_gargoyle_scan_timers', 'Detect Gargoyle/Ekko/Foliage sleep obfuscation via Waitable Timers.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/gargoyle/scan_waitable_timers', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_gargoyle_detect_rop_chains', 'Detect ROP APC chains used in sleep obfuscation.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/gargoyle/detect_rop_apc_chains', {}), null, 2) }] };
  });
  server.tool('x64dbg_gargoyle_find_suspicious_regions', 'Find non-executable private memory regions containing encrypted payloads.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/gargoyle/find_non_executable_suspicious_regions', { pid: pid ?? 0 }), null, 2) }] };
  });

  // Module Stomping
  server.tool('x64dbg_module_stomp_scan', 'Scan for Module Stomping across loaded DLLs in target process.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/module_stomp/scan_loaded_modules', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_module_stomp_compare_disk', 'Compare in-memory .text section SHA256 against on-disk image.', { module_name: z.string().describe('Module name') }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/module_stomp/compare_disk_vs_memory', { module_name }), null, 2) }] };
  });
  server.tool('x64dbg_module_stomp_detect_overwrites', 'Detect .text section overwrites and GHOST hollowing techniques.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/module_stomp/detect_text_section_overwrites', {}), null, 2) }] };
  });
}
