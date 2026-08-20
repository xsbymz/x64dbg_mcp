#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <algorithm>
#include <set>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

namespace {

std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return std::tolower(c); });
    return r;
}

struct canary_info {
    duint load_address;
    std::string load_disasm;
    duint check_address;
    std::string check_disasm;
    duint xor_address;
    std::string xor_disasm;
    duint fail_address;
    std::string fail_disasm;
    bool has_canary;
    bool has_xor;
    bool has_check;
    std::string canary_type;
};

canary_info analyze_function_canary(c_bridge_executor& bridge, duint func_start, duint func_end) {
    canary_info info{};
    info.has_canary = false;
    info.has_xor = false;
    info.has_check = false;
    info.canary_type = "none";

    for (duint addr = func_start; addr < func_end - 2; ) {
        auto d = bridge.get_basic_info(addr);
        if (!d.has_value()) { addr += 1; continue; }

        std::string inst = to_lower(d.value()["instruction"].get<std::string>());
        int size = d.value()["size"].get<int>();
        if (size <= 0) { addr += 1; continue; }

        if (!info.has_canary && (inst.find("gs:") != std::string::npos || inst.find("fs:") != std::string::npos)) {
            if (inst.find("mov") != std::string::npos && inst.find("rbp") != std::string::npos) {
                info.has_canary = true;
                info.load_address = addr;
                info.load_disasm = d.value()["instruction"].get<std::string>();
            }
        }

        if (info.has_canary && !info.has_xor && inst.find("xor") != std::string::npos &&
            (inst.find("rbp") != std::string::npos || inst.find("ebp") != std::string::npos)) {
            info.has_xor = true;
            info.xor_address = addr;
            info.xor_disasm = d.value()["instruction"].get<std::string>();
            info.canary_type = "terminator_canary";
        }

        if (!info.has_check && inst.find("__stack_chk_fail") != std::string::npos) {
            info.has_check = true;
            info.check_address = addr;
            info.check_disasm = d.value()["instruction"].get<std::string>();
        }

        if (info.has_check && !info.fail_address && inst.find("call") != std::string::npos &&
            inst.find("__stack_chk_fail") != std::string::npos) {
            info.fail_address = addr;
            info.fail_disasm = d.value()["instruction"].get<std::string>();
        }

        addr += size;
    }

    return info;
}

}

void register_stack_canary_routes(c_http_router& router) {
    router.post("/api/security/stack_canary_analyze", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string func = body.value("function_address", "cip");

        auto& bridge = get_bridge();
        duint start = bridge.eval_expression(func);
        auto bounds = bridge.get_function_bounds(start);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + func);
        }

        duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        auto info = analyze_function_canary(bridge, func_start, func_end);

        nlohmann::json result = {
            {"function", func},
            {"function_start", format_utils::format_address(func_start)},
            {"function_end", format_utils::format_address(func_end)},
            {"has_canary", info.has_canary},
            {"canary_type", info.canary_type},
            {"has_xor_protection", info.has_xor},
            {"has_check", info.has_check}
        };

        if (info.has_canary) {
            result["load_instruction"] = {
                {"address", format_utils::format_address(info.load_address)},
                {"disassembly", info.load_disasm}
            };
        }
        if (info.has_xor) {
            result["xor_instruction"] = {
                {"address", format_utils::format_address(info.xor_address)},
                {"disassembly", info.xor_disasm}
            };
        }
        if (info.has_check) {
            result["check_instruction"] = {
                {"address", format_utils::format_address(info.check_address)},
                {"disassembly", info.check_disasm}
            };
        }

        result["bypass_difficulty"] = info.has_canary ? "HIGH" : "LOW";
        result["bypass_techniques"] = info.has_canary ?
            nlohmann::json::array({"leak_canary_via_format_string", "bruteforce_fork_server", "stack_clash"}) :
            nlohmann::json::array({"direct_overflow", "ret2libc", "rop_chain"});

        return s_http_response::ok(result);
    });

    router.get("/api/security/stack_canary_status", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();
        auto bounds = bridge.get_function_bounds(cip);
        if (!bounds.has_value()) {
            return s_http_response::ok({
                {"status", "unknown"},
                {"message", "No function at current CIP"}
            });
        }

        duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        auto info = analyze_function_canary(bridge, func_start, func_end);

        return s_http_response::ok({
            {"status", info.has_canary ? "protected" : "unprotected"},
            {"canary_type", info.canary_type},
            {"current_function", format_utils::format_address(cip)},
            {"has_canary", info.has_canary},
            {"has_check", info.has_check}
        });
    });

    router.post("/api/security/scan_all_functions_canary", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string module = body.value("module", "");

        duint mod_base = 0;
        size_t mod_size = 0;
        if (!module.empty()) {
            mod_base = bridge.get_module_base(module);
            mod_size = static_cast<size_t>(bridge.eval_expression("mod.size(\"" + module + "\")"));
            if (mod_size == 0) mod_size = 0x10000;
        }
        if (mod_base == 0) {
            mod_base = bridge.get_cip();
            auto bounds = bridge.get_function_bounds(mod_base);
            if (bounds.has_value()) {
                mod_base = format_utils::parse_address(bounds.value()["start"].get<std::string>());
                mod_size = 0x10000;
            }
        }

        auto func_list = bridge.disassemble_at(mod_base, static_cast<int>(mod_size / 4));
        if (!func_list.has_value()) {
            return s_http_response::internal_error("Failed to disassemble module");
        }

        std::vector<nlohmann::json> protected_funcs;
        std::vector<nlohmann::json> unprotected_funcs;

        for (const auto& instr : func_list.value()) {
            std::string label = instr.value("label", "");
            if (label.empty()) continue;

            duint func_addr = format_utils::parse_address(instr["address"].get<std::string>());
            auto bounds = bridge.get_function_bounds(func_addr);
            if (!bounds.has_value()) continue;

            duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
            duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

            auto info = analyze_function_canary(bridge, func_start, func_end);
            nlohmann::json func_entry = {
                {"address", format_utils::format_address(func_start)},
                {"size", format_utils::format_hex(static_cast<duint>(func_end - func_start))},
                {"canary_type", info.canary_type}
            };

            if (info.has_canary) {
                protected_funcs.push_back(func_entry);
            } else {
                unprotected_funcs.push_back(func_entry);
            }
        }

        return s_http_response::ok({
            {"module", module.empty() ? "current" : module},
            {"module_base", format_utils::format_address(mod_base)},
            {"protected_count", protected_funcs.size()},
            {"unprotected_count", unprotected_funcs.size()},
            {"protected_functions", protected_funcs},
            {"unprotected_functions", unprotected_funcs}
        });
    });
}

}
