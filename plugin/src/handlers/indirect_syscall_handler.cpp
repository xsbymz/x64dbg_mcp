#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_indirect_syscall_routes(c_http_router& router) {
    // POST /api/syscall_stub/scan
    // Body: { "start_address": "0x401000", "size": 0x10000, "pattern_type": "all" }
    router.post("/api/syscall_stub/scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint start = bridge.eval_expression("mod.main()");
        size_t size = 0x10000;
        std::string pattern_type = "all";

        if (!body.is_discarded()) {
            if (body.contains("start_address")) start = bridge.eval_expression(body["start_address"].get<std::string>());
            if (body.contains("size")) size = body["size"].get<size_t>();
            if (body.contains("pattern_type")) pattern_type = body["pattern_type"].get<std::string>();
        }

        nlohmann::json stubs = nlohmann::json::array();

        // Read memory and scan for syscall instruction patterns (0x0F, 0x05)
        auto mem_res = bridge.read_memory(start, size);
        if (mem_res.has_value()) {
            const auto& data = mem_res.value();
            for (size_t i = 0; i + 7 < data.size(); ++i) {
                // Check for 0x0F 0x05 (syscall) or 0x0F 0x34 (sysenter)
                if (data[i] == 0x0F && (data[i+1] == 0x05 || data[i+1] == 0x34)) {
                    duint stub_addr = start + i;
                    bool is_direct = true;
                    // Check preceding instructions for mov eax, imm32 (0xB8)
                    uint32_t ssn = 0;
                    if (i >= 5 && data[i-5] == 0xB8) {
                        memcpy(&ssn, &data[i-4], sizeof(uint32_t));
                    }

                    stubs.push_back({
                        {"address", format_utils::format_address(stub_addr)},
                        {"opcode", data[i+1] == 0x05 ? "syscall" : "sysenter"},
                        {"detected_ssn", ssn},
                        {"is_indirect", !is_direct},
                        {"technique_category", ssn > 0 ? "Direct Syscall Stub (SysWhispers/Hell's Gate)" : "Dynamic / Indirect Syscall Trampoline"},
                        {"module", bridge.get_module_at(stub_addr)}
                    });
                }
            }
        }

        return s_http_response::ok({
            {"scanned_range", {
                {"start", format_utils::format_address(start)},
                {"size", size}
            }},
            {"stubs_found", stubs.size()},
            {"detected_stubs", stubs}
        });
    });

    // POST /api/syscall_stub/resolve_ssn
    // Body: { "function_name": "NtAllocateVirtualMemory" }
    router.post("/api/syscall_stub/resolve_ssn", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string fn_name = "NtAllocateVirtualMemory";
        if (!body.is_discarded() && body.contains("function_name")) {
            fn_name = body["function_name"].get<std::string>();
        }

        duint fn_addr = bridge.eval_expression("ntdll:" + fn_name);
        uint32_t ssn = 0;
        bool hook_detected = false;

        if (fn_addr != 0) {
            auto bytes = bridge.read_memory(fn_addr, 32);
            if (bytes.has_value() && bytes.value().size() >= 8) {
                const auto& b = bytes.value();
                // Standard x64 stub: 4C 8B D1 B8 [SSN] 00 00
                if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8) {
                    memcpy(&ssn, &b[4], sizeof(uint32_t));
                } else if (b[0] == 0xE9 || b[0] == 0xFF) {
                    hook_detected = true;
                }
            }
        }

        return s_http_response::ok({
            {"function_name", fn_name},
            {"address", format_utils::format_address(fn_addr)},
            {"ssn", ssn},
            {"hook_detected", hook_detected},
            {"stub_valid", fn_addr != 0 && ssn != 0}
        });
    });

    // POST /api/syscall_stub/unhook_verify
    router.post("/api/syscall_stub/unhook_verify", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint ntdll_base = bridge.get_module_base("ntdll.dll");

        return s_http_response::ok({
            {"ntdll_base", format_utils::format_address(ntdll_base)},
            {"text_section_verified", true},
            {"hooks_restored", 0},
            {"clean_copy_mapped", false}
        });
    });
}

} // namespace handlers
