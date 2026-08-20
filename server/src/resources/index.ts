import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { httpClient } from '../http_client.js';

export function registerAllResources(server: McpServer) {
  // x64dbg://state - Live debugger execution state
  server.resource(
    'x64dbg-state',
    'x64dbg://state',
    {
      description: 'Current execution state of the x64dbg target process (running, paused, stopped, PID, TID)',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const state = await httpClient.get('/api/debug/state');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(state, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://registers - Live CPU registers (GPRs, flags, AVX-512)
  server.resource(
    'x64dbg-registers',
    'x64dbg://registers',
    {
      description: 'Current CPU register values (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, RIP, R8-R15, EFLAGS)',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const regs = await httpClient.get('/api/registers/all');
        const flags = await httpClient.get('/api/registers/flags');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ registers: regs, flags }, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://stack/top - Top stack entries with dereferenced labels
  server.resource(
    'x64dbg-stack-top',
    'x64dbg://stack/top',
    {
      description: 'Top stack entries (RSP) with dereferenced pointer symbols and modules',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const stack = await httpClient.get('/api/stack/read', { address: 'csp', size: '256' });
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(stack, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://disasm/cip - Disassembly around current instruction pointer
  server.resource(
    'x64dbg-disasm-cip',
    'x64dbg://disasm/cip',
    {
      description: 'Disassembly around current CIP (instruction pointer) with basic blocks and branch info',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const disasm = await httpClient.get('/api/disasm/at', { address: 'cip', count: '20' });
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(disasm, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://callstack - Reconstructed call stack frames
  server.resource(
    'x64dbg-callstack',
    'x64dbg://callstack',
    {
      description: 'Reconstructed call stack frames with return addresses and module names',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const cs = await httpClient.get('/api/stack/trace', { max_depth: '50' });
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(cs, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://modules - Loaded modules
  server.resource(
    'x64dbg-modules',
    'x64dbg://modules',
    {
      description: 'List of all loaded PE modules with base addresses, sizes, and paths',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const mods = await httpClient.get('/api/modules/list');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(mods, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://breakpoints - Active breakpoints
  server.resource(
    'x64dbg-breakpoints',
    'x64dbg://breakpoints',
    {
      description: 'All active software, hardware, and memory breakpoints with hit counts and conditions',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const bps = await httpClient.get('/api/breakpoints/list');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(bps, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://patches - Applied patches
  server.resource(
    'x64dbg-patches',
    'x64dbg://patches',
    {
      description: 'List of all active byte patches in the debugged process vs original binary bytes',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const patches = await httpClient.get('/api/patches/list');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(patches, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://seh - Structured Exception Handling (SEH) chain
  server.resource(
    'x64dbg-seh',
    'x64dbg://seh',
    {
      description: 'Current Structured Exception Handling (SEH) record chain',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const seh = await httpClient.get('/api/exceptions/seh_chain');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(seh, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://antidebug/audit - Anti-debug detection & stealth audit
  server.resource(
    'x64dbg-antidebug-audit',
    'x64dbg://antidebug/audit',
    {
      description: 'Comprehensive anti-debugging audit: PEB BeingDebugged, NtGlobalFlag, Hardware BPs, DEP, and stealth status',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const audit = await httpClient.get('/api/antidebug/audit');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(audit, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://threads/all - Full multi-thread snapshot
  server.resource(
    'x64dbg-threads-all',
    'x64dbg://threads/all',
    {
      description: 'Complete list of all active threads with CIP, TEB, Name, and current active status',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const threads = await httpClient.get('/api/threads/contexts_all');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(threads, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://stack/arguments - Current function parameters & resolved values
  server.resource(
    'x64dbg-stack-arguments',
    'x64dbg://stack/arguments',
    {
      description: 'Current function caller parameters and dereferenced string/pointer values',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const args = await httpClient.get('/api/stack/arguments', { count: '8' });
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(args, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://antidebug/hooks - User-mode API & Syscall Hook Auditor report
  server.resource(
    'x64dbg-antidebug-hooks',
    'x64dbg://antidebug/hooks',
    {
      description: 'Audit report of intercepted, detoured, or modified NTDLL / Kernel32 syscalls and APIs',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const hooks = await httpClient.get('/api/antidebug/hooks');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(hooks, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // x64dbg://memory/rwx - W^X and unbacked executable allocations
  server.resource(
    'x64dbg-memory-rwx',
    'x64dbg://memory/rwx',
    {
      description: 'Audit of PAGE_EXECUTE_READWRITE (RWX) allocations and unbacked private executable memory regions',
      mimeType: 'application/json'
    },
    async (uri) => {
      try {
        const rwx = await httpClient.get('/api/memory/rwx_audit');
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify(rwx, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (err) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );
}
