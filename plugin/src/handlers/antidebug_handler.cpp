#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_antidebug_routes(c_http_router& router) {
    // GET /api/antidebug/peb?pid= - Read PEB info
    router.get("/api/antidebug/peb", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid_str = req.get_query("pid", "");
        DWORD pid = 0;
        if (pid_str.empty()) {
            pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        } else {
            pid = static_cast<DWORD>(std::stoul(pid_str));
        }

        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::not_found("Failed to get PEB address");
        }

        nlohmann::json data = {
            {"peb_address", format_utils::format_address(peb_addr)},
            {"pid", pid}
        };

        // Read BeingDebugged (offset 0x2 in PEB, 1 byte)
        auto being_debugged = bridge.read_memory(peb_addr + 0x2, 1);
        if (being_debugged.has_value()) {
            data["being_debugged"] = being_debugged.value()[0];
        }

        // Read NtGlobalFlag (offset 0x68 on x86, 0xBC on x64)
#ifdef _WIN64
        constexpr duint ntglobalflag_offset = 0xBC;
#else
        constexpr duint ntglobalflag_offset = 0x68;
#endif
        auto ntglobal = bridge.read_memory(peb_addr + ntglobalflag_offset, 4);
        if (ntglobal.has_value()) {
            DWORD flags = 0;
            memcpy(&flags, ntglobal.value().data(), 4);
            data["nt_global_flag"] = format_utils::format_address(flags);
            data["nt_global_flag_decimal"] = flags;
        }

        // Read ProcessHeap (offset 0x18 on x86, 0x30 on x64)
#ifdef _WIN64
        constexpr duint heap_offset = 0x30;
#else
        constexpr duint heap_offset = 0x18;
#endif
        auto heap_data = bridge.read_memory(peb_addr + heap_offset, sizeof(duint));
        if (heap_data.has_value()) {
            duint heap_addr = 0;
            memcpy(&heap_addr, heap_data.value().data(), sizeof(duint));
            data["process_heap"] = format_utils::format_address(heap_addr);
        }

        return s_http_response::ok(data);
    });

    // GET /api/antidebug/teb?tid= - Read TEB info
    router.get("/api/antidebug/teb", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto tid_str = req.get_query("tid", "");
        DWORD tid = 0;
        if (tid_str.empty()) {
            tid = static_cast<DWORD>(bridge.eval_expression("$tid"));
        } else {
            tid = static_cast<DWORD>(std::stoul(tid_str));
        }

        auto teb_addr = DbgGetTebAddress(tid);
        if (teb_addr == 0) {
            return s_http_response::not_found("Failed to get TEB address");
        }

        nlohmann::json data = {
            {"teb_address", format_utils::format_address(teb_addr)},
            {"tid", tid}
        };

        // Read SEH chain pointer (offset 0x0 in TEB)
        auto seh = bridge.read_memory(teb_addr, sizeof(duint));
        if (seh.has_value()) {
            duint seh_addr = 0;
            memcpy(&seh_addr, seh.value().data(), sizeof(duint));
            data["seh_frame"] = format_utils::format_address(seh_addr);
        }

        // Read stack base (offset 0x4/0x8) and limit (offset 0x8/0x10)
#ifdef _WIN64
        constexpr duint stack_base_offset = 0x8;
        constexpr duint stack_limit_offset = 0x10;
        constexpr duint peb_offset = 0x60;
#else
        constexpr duint stack_base_offset = 0x4;
        constexpr duint stack_limit_offset = 0x8;
        constexpr duint peb_offset = 0x30;
#endif

        auto stack_base = bridge.read_memory(teb_addr + stack_base_offset, sizeof(duint));
        if (stack_base.has_value()) {
            duint val = 0;
            memcpy(&val, stack_base.value().data(), sizeof(duint));
            data["stack_base"] = format_utils::format_address(val);
        }

        auto stack_limit = bridge.read_memory(teb_addr + stack_limit_offset, sizeof(duint));
        if (stack_limit.has_value()) {
            duint val = 0;
            memcpy(&val, stack_limit.value().data(), sizeof(duint));
            data["stack_limit"] = format_utils::format_address(val);
        }

        auto peb = bridge.read_memory(teb_addr + peb_offset, sizeof(duint));
        if (peb.has_value()) {
            duint val = 0;
            memcpy(&val, peb.value().data(), sizeof(duint));
            data["peb_address"] = format_utils::format_address(val);
        }

        return s_http_response::ok(data);
    });

    // POST /api/antidebug/hide_debugger - Hide debugger from PEB
    router.post("/api/antidebug/hide_debugger", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::internal_error("Failed to get PEB address");
        }

        nlohmann::json changes = nlohmann::json::array();

        // Zero out BeingDebugged (PEB + 0x2)
        std::vector<uint8_t> zero_byte = {0x00};
        auto result = bridge.write_memory(peb_addr + 0x2, zero_byte);
        if (result.has_value()) {
            changes.push_back({{"field", "BeingDebugged"}, {"offset", "0x2"}, {"value", 0}});
        }

        // Zero out NtGlobalFlag
#ifdef _WIN64
        constexpr duint ntglobalflag_offset = 0xBC;
#else
        constexpr duint ntglobalflag_offset = 0x68;
#endif
        std::vector<uint8_t> zero_dword = {0x00, 0x00, 0x00, 0x00};
        result = bridge.write_memory(peb_addr + ntglobalflag_offset, zero_dword);
        if (result.has_value()) {
            changes.push_back({{"field", "NtGlobalFlag"}, {"offset", format_utils::format_hex(ntglobalflag_offset)}, {"value", 0}});
        }

        return s_http_response::ok({
            {"peb_address", format_utils::format_address(peb_addr)},
            {"changes", changes},
            {"message", "Debugger hidden from PEB checks"}
        });
    });

    // GET /api/antidebug/dep_status - DEP enabled status
    router.get("/api/antidebug/dep_status", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto dep_enabled = DbgFunctions()->IsDepEnabled();

        return s_http_response::ok({
            {"dep_enabled", dep_enabled}
        });
    });

    // GET /api/antidebug/audit - Comprehensive Anti-Debug Vulnerability & Telemetry Audit
    router.get("/api/antidebug/audit", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        auto peb_addr = DbgGetPebAddress(pid);

        auto findings = nlohmann::json::array();
        int score_detected = 0;

        // 1. BeingDebugged
        uint8_t being_debugged = 0;
        if (peb_addr != 0) {
            auto mem = bridge.read_memory(peb_addr + 0x2, 1);
            if (mem.has_value() && !mem->empty()) {
                being_debugged = (*mem)[0];
                if (being_debugged != 0) {
                    findings.push_back({
                        {"check",       "PEB.BeingDebugged"},
                        {"status",      "DETECTABLE"},
                        {"value",       being_debugged},
                        {"remediation", "Use POST /api/antidebug/hide_debugger to zero PEB.BeingDebugged"}
                    });
                    score_detected++;
                }
            }
        }

        // 2. NtGlobalFlag
#ifdef _WIN64
        constexpr duint ntglobalflag_offset = 0xBC;
#else
        constexpr duint ntglobalflag_offset = 0x68;
#endif
        DWORD nt_global_flags = 0;
        if (peb_addr != 0) {
            auto mem = bridge.read_memory(peb_addr + ntglobalflag_offset, 4);
            if (mem.has_value() && mem->size() >= 4) {
                std::memcpy(&nt_global_flags, mem->data(), 4);
                if (nt_global_flags & 0x70) { // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
                    findings.push_back({
                        {"check",       "PEB.NtGlobalFlag"},
                        {"status",      "DETECTABLE"},
                        {"value",       format_utils::format_hex(nt_global_flags)},
                        {"remediation", "Use POST /api/antidebug/hide_debugger to zero NtGlobalFlag"}
                    });
                    score_detected++;
                }
            }
        }

        // 3. Hardware Breakpoints (DR0..DR3)
        auto dr0 = bridge.eval_expression("dr0");
        auto dr1 = bridge.eval_expression("dr1");
        auto dr2 = bridge.eval_expression("dr2");
        auto dr3 = bridge.eval_expression("dr3");
        auto dr7 = bridge.eval_expression("dr7");
        bool hw_bp_active = (dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0 || dr7 != 0);
        if (hw_bp_active) {
            findings.push_back({
                {"check",       "Hardware Breakpoints (Debug Registers)"},
                {"status",      "VISIBLE_TO_CONTEXT_QUERIES"},
                {"value",       format_utils::format_hex(dr7)},
                {"remediation", "Target can detect hardware BPs via GetThreadContext / NtGetContextThread"}
            });
        }

        // 4. DEP & Elevation status
        bool dep_enabled = DbgFunctions()->IsDepEnabled();
        bool elevated = DbgFunctions()->IsProcessElevated();

        return s_http_response::ok({
            {"peb_address",     format_utils::format_address(peb_addr)},
            {"being_debugged",  being_debugged},
            {"nt_global_flags", format_utils::format_hex(nt_global_flags)},
            {"hw_breakpoints",  hw_bp_active},
            {"dep_enabled",     dep_enabled},
            {"elevated",        elevated},
            {"detection_score", score_detected},
            {"stealth_status",  score_detected == 0 ? "STEALTH_OPTIMAL" : "DETECTABLE_BY_ANTI_DEBUG"},
            {"findings",        findings}
        });
    });

    // GET /api/antidebug/hooks - User-mode API & Syscall Hook Auditor
    // Checks critical NTDLL / Kernel32 APIs for inline JMP hooks, detours, and EDR/AV interception.
    router.get("/api/antidebug/hooks", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        const char* target_apis[] = {
            "ntdll:NtAllocateVirtualMemory",
            "ntdll:NtProtectVirtualMemory",
            "ntdll:NtWriteVirtualMemory",
            "ntdll:NtReadVirtualMemory",
            "ntdll:NtCreateThreadEx",
            "ntdll:NtQueueApcThread",
            "ntdll:NtUnmapViewOfSection",
            "ntdll:NtMapViewOfSection",
            "ntdll:NtOpenProcess",
            "ntdll:NtSetContextThread",
            "ntdll:NtGetContextThread",
            "ntdll:NtQueryInformationProcess",
            "kernel32:VirtualAlloc",
            "kernel32:VirtualProtect",
            "kernel32:WriteProcessMemory",
            "kernel32:CreateRemoteThread",
            "kernel32:LoadLibraryA",
            "kernel32:LoadLibraryW"
        };

        auto hooked = nlohmann::json::array();
        auto clean = nlohmann::json::array();

        for (const auto& api_name : target_apis) {
            duint addr = bridge.eval_expression(api_name);
            if (addr == 0) continue;

            auto mem = bridge.read_memory(addr, 16);
            if (!mem.has_value() || mem->size() < 5) continue;

            const auto& bytes = *mem;
            bool is_hooked = false;
            std::string hook_type = "clean";
            duint dest_addr = 0;

            // Check for 0xE9 (JMP rel32)
            if (bytes[0] == 0xE9) {
                is_hooked = true;
                hook_type = "inline_jmp_rel32";
                int32_t rel = 0;
                std::memcpy(&rel, &bytes[1], 4);
                dest_addr = addr + 5 + static_cast<duint>(rel);
            }
            // Check for 0xFF 0x25 (JMP [rip+rel32] or JMP [abs32])
            else if (bytes[0] == 0xFF && bytes[1] == 0x25) {
                is_hooked = true;
                hook_type = "indirect_jmp";
            }
            // Check for 0xCC (Software Breakpoint INT3)
            else if (bytes[0] == 0xCC) {
                is_hooked = true;
                hook_type = "software_breakpoint_int3";
            }
#ifdef _WIN64
            // Check x64 NTDLL syscall prologue:
            // Standard clean x64 NTDLL syscall starts with: 4C 8B D1 (mov r10, rcx)
            else if (std::string(api_name).rfind("ntdll:Nt", 0) == 0) {
                if (!(bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1)) {
                    is_hooked = true;
                    hook_type = "modified_syscall_prologue";
                }
            }
#endif

            nlohmann::json item = {
                {"api",         api_name},
                {"address",     format_utils::format_address(addr)},
                {"first_bytes", format_utils::format_bytes_hex(bytes.data(), std::min<size_t>(bytes.size(), 8))},
                {"hook_type",   hook_type}
            };

            if (is_hooked) {
                if (dest_addr != 0) {
                    item["destination"] = format_utils::format_address(dest_addr);
                    item["dest_module"] = bridge.get_module_at(dest_addr);
                    item["dest_label"]  = bridge.get_label_at(dest_addr);
                }
                hooked.push_back(item);
            } else {
                clean.push_back(item);
            }
        }

        return s_http_response::ok({
            {"hooked_count", hooked.size()},
            {"clean_count",  clean.size()},
            {"hooked_apis",  hooked},
            {"clean_apis",   clean}
        });
    });
}

} // namespace handlers
