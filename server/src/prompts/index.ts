import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerAllPrompts(server: McpServer) {
  // Prompt 1: unpack_oep_finder
  server.prompt(
    'unpack_oep_finder',
    'Playbook for unpacking packed binaries (UPX, Themida, VMProtect, custom packers) and locating Original Entry Point (OEP)',
    {
      module: z.string().optional().describe('Target module name (defaults to main executable)')
    },
    ({ module }) => {
      const target = module ?? 'main executable';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `You are an expert reverse engineer using x64dbg. Help me unpack ${target} and find the Original Entry Point (OEP).\n\n` +
                    `Recommended workflow:\n` +
                    `1. Use \`x64dbg_pe\` with action \`tls_callbacks\` to check if code executes before entry point.\n` +
                    `2. Inspect memory map sections using \`x64dbg_memory\` action \`map\` to identify packed sections (e.g. UPX0, .vmp, empty .text with non-zero VirtualSize).\n` +
                    `3. Set hardware execute breakpoint (or memory write breakpoint) on the .text section: \`x64dbg_breakpoints\` action \`set_hardware\`.\n` +
                    `4. Run the debugger with \`x64dbg_debug\` action \`run\` followed by \`wait_event\` until the unpacker writes/executes the unpacked code.\n` +
                    `5. Trace tail jumps (long \`jmp\` or \`call\` targeting a different section base) to identify OEP.\n` +
                    `6. Once at OEP, dump the unpacked module with \`x64dbg_dumping\` action \`module\`.`
            }
          }
        ]
      };
    }
  );

  // Prompt 2: diagnose_crash
  server.prompt(
    'diagnose_crash',
    'Analyze an active crash / exception in x64dbg (Access Violation, Null Dereference, UAF, Stack Overflow)',
    {},
    () => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Diagnose the root cause of the current crash in x64dbg.\n\n` +
                    `Please perform the following diagnostic steps:\n` +
                    `1. Read the current execution state, CIP, and last exception with \`x64dbg_debug\` action \`state\` and \`x64dbg_exceptions\` action \`seh_chain\`.\n` +
                    `2. Inspect all registers (\`x64dbg_registers\` action \`get_all\`) and the faulting instruction at CIP (\`x64dbg_disassembly\` action \`at_address\`, count 5).\n` +
                    `3. Examine stack memory around RSP (\`x64dbg_stack\` action \`read\`) and reconstruct the call stack (\`x64dbg_stack\` action \`trace\`).\n` +
                    `4. Check memory page permissions for any invalid pointers referenced by the faulting instruction (\`x64dbg_memory\` action \`info\`).\n` +
                    `5. Conclude the vulnerability/bug class (e.g., NULL pointer dereference, Use-After-Free, out-of-bounds write) and identify the offending function.`
            }
          }
        ]
      };
    }
  );

  // Prompt 3: crypto_identifier
  server.prompt(
    'crypto_identifier',
    'Scan process memory for cryptographic algorithms (AES, SHA, MD5, ChaCha20, RSA, CRC32) and locate key generation/encryption routines',
    {
      module: z.string().optional().describe('Module to scan (omit for entire process memory)')
    },
    ({ module }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Find and analyze cryptographic operations in the current debugging session${module ? ` for module ${module}` : ''}.\n\n` +
                    `Steps to take:\n` +
                    `1. Run \`x64dbg_crypto\` action \`scan\`${module ? ` with module: "${module}"` : ''} to locate AES S-boxes, hash initializers, and cipher constants.\n` +
                    `2. For each discovered constant, query cross-references using \`x64dbg_analysis\` action \`xrefs_to\` to identify encryption functions.\n` +
                    `3. Disassemble the cryptographic routine with \`x64dbg_disassembly\` action \`function\`.\n` +
                    `4. Set breakpoints on entry/exit to capture keys and plaintext buffers.`
            }
          }
        ]
      };
    }
  );

  // Prompt 4: anti_anti_debug_triage
  server.prompt(
    'anti_anti_debug_triage',
    'Audit and neutralize anti-debugging mechanisms (PEB flags, NtGlobalFlag, timing checks, hardware breakpoint detection, SEH hooks)',
    {},
    () => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Inspect and bypass anti-debugging protections in the target process.\n\n` +
                    `Recommended checklist:\n` +
                    `1. Audit PEB: Check \`BeingDebugged\`, \`NtGlobalFlag\`, and \`ProcessHeap\` flags using \`x64dbg_antidebug\` action \`get_peb\`.\n` +
                    `2. Clear PEB flags with \`x64dbg_antidebug\` action \`hide_debugger\`.\n` +
                    `3. Enable telemetry on anti-debug APIs with \`x64dbg_telemetry\` action \`enable\`, category \`anti_debug\`.\n` +
                    `4. Check for hardware breakpoint clearing (GetThreadContext / SetThreadContext) and SEH registration tricks.`
            }
          }
        ]
      };
    }
  );

  // Prompt 5: api_behavior_profiler
  server.prompt(
    'api_behavior_profiler',
    'Set up automated telemetry on Windows APIs (File I/O, Registry, Process Injection, Network C2) to observe program behavior',
    {
      category: z.enum(['all', 'file_io', 'registry', 'injection', 'network', 'anti_debug']).optional().default('all')
    },
    ({ category }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Start monitoring the target process's behavior for category: **${category}**.\n\n` +
                    `Instructions:\n` +
                    `1. Enable telemetry hooks via \`x64dbg_telemetry\` action \`enable\` with category: "${category}".\n` +
                    `2. Resume execution using \`x64dbg_debug\` action \`run\`.\n` +
                    `3. Review generated logs or wait for events with \`x64dbg_debug\` action \`wait_event\`.\n` +
                    `4. Summarize observed files created, registry keys touched, injected memory addresses, or network connections.`
            }
          }
        ]
      };
    }
  );

  // Prompt 6: xor_string_deobfuscator
  server.prompt(
    'xor_string_deobfuscator',
    'Brute-force scan memory for XOR-encrypted C2 URLs, API names, or registry keys across all 256 single-byte keys',
    {
      target: z.string().describe('Target plaintext keyword to search for under XOR obfuscation (e.g. "http", "cmd.exe", "powershell", "VirtualAlloc")'),
      module: z.string().optional().describe('Restrict scan to module name (optional)')
    },
    ({ target, module }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Deobfuscate XOR-encoded strings matching "${target}" in memory${module ? ` for module ${module}` : ''}.\n\n` +
                    `Procedure:\n` +
                    `1. Run \`x64dbg_search\` action \`xor_scan\` with query: "${target}"${module ? `, module: "${module}"` : ''}.\n` +
                    `2. For every match, observe the discovered XOR key and address.\n` +
                    `3. Read surrounding memory with \`x64dbg_memory\` action \`read\` and apply the key to decode the entire string or configuration buffer.\n` +
                    `4. Check cross-references to the decoded buffer using \`x64dbg_analysis\` action \`xrefs_to\` to identify the string decryption loop.`
            }
          }
        ]
      };
    }
  );

  // Prompt 7: edr_hook_hunter
  server.prompt(
    'edr_hook_hunter',
    'Audit loaded modules and NTDLL syscalls for inline detours, EDR hooks, and security software trampolines',
    {},
    () => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Audit the process for inline hooks, AV/EDR detours, and modified syscall stubs.\n\n` +
                    `Procedure:\n` +
                    `1. Run \`x64dbg_antidebug\` action \`hooks\` to scan critical NTDLL and Kernel32 APIs.\n` +
                    `2. For each detected hook, inspect the hook destination module and symbol.\n` +
                    `3. Read the prologue bytes using \`x64dbg_disassembly\` action \`at_address\` to confirm the detour type (JMP rel32, indirect JMP, or INT3).\n` +
                    `4. Compare against clean on-disk NTDLL syscall IDs to understand which functions are being monitored or intercepted.`
            }
          }
        ]
      };
    }
  );

  // Prompt 8: rop_chain_planner
  server.prompt(
    'rop_chain_planner',
    'Scan executable modules for ROP gadgets and plan return-oriented sequences (pop registers, stack pivots, memory writes)',
    {
      module: z.string().optional().describe('Target module to scan for gadgets (e.g. "ntdll.dll" or main binary)'),
      filter: z.enum(['all', 'pop', 'pivot', 'xchg', 'mov', 'syscall']).optional().default('all')
    },
    ({ module, filter }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Search and classify ROP/JOP gadgets in ${module ? `module "${module}"` : 'executable memory'} with filter "${filter}".\n\n` +
                    `Procedure:\n` +
                    `1. Run \`x64dbg_analysis\` action \`rop_gadgets\` with query: "${module ?? ''}", filter: "${filter}".\n` +
                    `2. Catalog essential gadget types:\n` +
                    `   - Register loaders (\`pop rcx; ret\`, \`pop rdx; ret\`, \`pop r8; ret\`, \`pop r9; ret\`)\n` +
                    `   - Stack pivots (\`xchg rax, rsp; ret\`, \`mov rsp, ...; ret\`, \`add rsp, ...; ret\`)\n` +
                    `   - Memory write primitives (\`mov [rax], rdx; ret\`)\n` +
                    `   - Direct syscall / sysenter gadgets\n` +
                    `3. Verify gadget addresses against module base addresses and ASLR status.`
            }
          }
        ]
      };
    }
  );

  // Prompt 9: binary_hardening_audit
  server.prompt(
    'binary_hardening_audit',
    'Perform a comprehensive security mitigation assessment (Checksec) and memory W^X integrity audit on the target executable',
    {
      module: z.string().describe('Target module name (e.g. "main.exe", "target.dll")')
    },
    ({ module }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Perform a comprehensive binary hardening and vulnerability surface audit for module **${module}**.\n\n` +
                    `Procedure:\n` +
                    `1. Run \`x64dbg_pe\` action \`mitigations\` with module: "${module}" to check ASLR, High Entropy VA, DEP/NX, SafeSEH, CFG, /GS Stack Cookies, and AppContainer.\n` +
                    `2. Audit memory page permissions with \`x64dbg_memory\` action \`rwx_audit\` to detect W^X violations or unbacked executable allocations.\n` +
                    `3. Check user-mode hook tampering with \`x64dbg_antidebug\` action \`hooks\`.\n` +
                    `4. Calculate section entropy with \`x64dbg_analysis\` action \`entropy\` with query: "${module}" to identify packed code.\n` +
                    `5. Summarize the overall security posture and attack surface.`
            }
          }
        ]
      };
    }
  );

  // Prompt 10: vtable_class_reconstructor
  server.prompt(
    'vtable_class_reconstructor',
    'Reconstruct C++ virtual function table layout, method prototypes, and inheritance hierarchy from an object pointer',
    {
      address: z.string().describe('C++ object instance pointer (this) or VTable address (e.g. "rcx" or "0x7FF712340000")')
    },
    ({ address }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Reconstruct the C++ class interface and VTable methods from address **${address}**.\n\n` +
                    `Procedure:\n` +
                    `1. Run \`x64dbg_analysis\` action \`vtable\` with query: "${address}".\n` +
                    `2. For each virtual method slot, inspect the entry point disassembly and resolved symbol.\n` +
                    `3. Identify common standard COM/C++ interfaces (e.g. QueryInterface, AddRef, Release, destructors).\n` +
                    `4. Generate a clean C++ abstract class header definition representing the reconstructed interface.`
            }
          }
        ]
      };
    }
  );

  // Prompt 11: register_provenance_slicer
  server.prompt(
    'register_provenance_slicer',
    'Trace backward through instructions to determine how a register value was computed (memory load, arithmetic, immediate, call)',
    {
      register: z.string().default('rax').describe('Target register to slice (e.g. "rax", "rcx", "rsp", "rbx")'),
      address: z.string().optional().default('cip').describe('Starting address to slice backwards from')
    },
    ({ register, address }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Perform backward data-flow dependency slicing on register **${register}** starting from **${address}**.\n\n` +
                    `Procedure:\n` +
                    `1. Run \`x64dbg_analysis\` action \`dataflow\` with query: "${address}", register: "${register}", depth: 25.\n` +
                    `2. Identify the defining instruction and the classification (memory load, pointer math, arithmetic computation, or function return).\n` +
                    `3. If it originated from memory, read the source memory address with \`x64dbg_memory\` action \`read\` or cast it with \`struct_view\`.\n` +
                    `4. Conclude how the register value was constructed.`
            }
          }
        ]
      };
    }
  );
}
