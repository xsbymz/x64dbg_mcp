#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

namespace handlers {

static std::string get_module_name_for_addr(duint addr) {
    char mod_name[MAX_PATH] = {};
    if (DbgGetModuleAt(addr, mod_name)) {
        return std::string(mod_name);
    }
    return {};
}

static nlohmann::json analyze_syscall_stub(duint addr, const std::vector<uint8_t>& bytes) {
    nlohmann::json result;
    result["address"] = format_utils::format_address(addr);
    duint mod_base = DbgFunctions()->ModBaseFromAddr(addr);
    result["rva"] = format_utils::format_address(mod_base != 0 ? addr - mod_base : 0);

    std::string first_hex = format_utils::format_bytes_hex(bytes.data(), std::min<size_t>(bytes.size(), 16));
    result["first_bytes"] = first_hex;

    duint ssn = 0;
    bool has_ssn = false;

    if (bytes.size() >= 5) {
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
            uint32_t imm = 0;
            std::memcpy(&imm, &bytes[4], 4);
            ssn = static_cast<duint>(imm);
            has_ssn = true;
        } else if (bytes[0] == 0xB8) {
            uint32_t imm = 0;
            std::memcpy(&imm, &bytes[1], 4);
            ssn = static_cast<duint>(imm);
            has_ssn = true;
        }
    }
    result["syscall_id"] = has_ssn ? format_utils::format_address(ssn) : "N/A";

    bool is_hooked = false;
    std::string hook_type = "clean";
    if (bytes.size() >= 2) {
        if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            is_hooked = true;
            hook_type = "inline_jmp";
        } else if (bytes[0] == 0xCC) {
            is_hooked = true;
            hook_type = "int3";
        } else if (bytes.size() >= 6 && bytes[0] == 0xE9) {
            is_hooked = true;
            hook_type = "inline_jmp";
        } else {
            bool matches_syscall = (bytes.size() >= 5 && bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8);
            if (!matches_syscall) {
                is_hooked = true;
                hook_type = "patch";
            }
        }
    }
    result["is_hooked"] = is_hooked;
    result["hook_type"] = hook_type;

    return result;
}

static void collect_module_exports(const std::string& module_name, bool detect_hooks, nlohmann::json& out) {
    auto& bridge = get_bridge();
    auto base = bridge.get_module_base(module_name);
    if (base == 0) return;

    auto exports = bridge.eval_expression("mod.exports(" + module_name + ")");
    if (exports == 0) return;

    for (duint i = 0; i < 256; ++i) {
        auto fn_name = bridge.eval_expression("mod.exopa(" + module_name + ", " + std::to_string(i) + ")");
        if (fn_name == 0) break;

        std::string fn_str = std::to_string(fn_name);
        auto fn_addr = bridge.eval_expression(module_name + "." + fn_str);
        if (fn_addr == 0 || fn_addr < base) continue;

        auto mem = bridge.read_memory(fn_addr, 16);
        if (!mem.has_value() || mem->size() < 2) continue;

        const auto& bytes = *mem;
        auto entry = nlohmann::json::object();
        entry["name"] = fn_str;
        entry["address"] = format_utils::format_address(fn_addr);
        entry["rva"] = format_utils::format_address(fn_addr - base);

        if (detect_hooks) {
            bool is_hooked = false;
            std::string hook_type = "clean";
            if (bytes[0] == 0xFF && bytes[1] == 0x25) {
                is_hooked = true;
                hook_type = "inline_jmp";
            } else if (bytes[0] == 0xCC) {
                is_hooked = true;
                hook_type = "int3";
            } else if (bytes.size() >= 6 && bytes[0] == 0xE9) {
                is_hooked = true;
                hook_type = "inline_jmp";
            }
            entry["is_hooked"] = is_hooked;
            entry["hook_type"] = hook_type;
            entry["first_bytes"] = format_utils::format_bytes_hex(bytes.data(), std::min<size_t>(bytes.size(), 8));
            if (is_hooked) {
                out.push_back(entry);
            }
        } else {
            out.push_back(entry);
        }
    }
}

void register_syscall_routes(c_http_router& router) {
    router.get("/api/syscalls/ntdll", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto ntdll_base = bridge.get_module_base("ntdll");
        if (ntdll_base == 0) {
            return s_http_response::not_found("ntdll not loaded");
        }

        nlohmann::json result = nlohmann::json::array();

        for (int i = 0; i < 512; ++i) {
            auto fn_name = bridge.eval_expression("mod.exopa(ntdll, " + std::to_string(i) + ")");
            if (fn_name == 0) break;

            std::string fn_str = std::to_string(fn_name);
            auto fn_addr = bridge.eval_expression("ntdll." + fn_str);
            if (fn_addr == 0 || fn_addr < ntdll_base) continue;

            auto mem = bridge.read_memory(fn_addr, 16);
            if (!mem.has_value() || mem->size() < 5) continue;

            auto entry = analyze_syscall_stub(fn_addr, *mem);
            entry["name"] = fn_str;
            result.push_back(entry);
        }

        return s_http_response::ok({
            {"module",    "ntdll"},
            {"base",      format_utils::format_address(ntdll_base)},
            {"count",     result.size()},
            {"syscalls",  result}
        });
    });

    router.get("/api/syscalls/ssn", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto name = req.get_query("name");
        if (name.empty()) {
            return s_http_response::bad_request("Missing 'name' query parameter");
        }

        auto fn_addr = bridge.eval_expression("ntdll." + name);
        if (fn_addr == 0) {
            return s_http_response::not_found("Export not found: " + name);
        }

        auto mem = bridge.read_memory(fn_addr, 16);
        if (!mem.has_value() || mem->size() < 5) {
            return s_http_response::internal_error("Failed to read first bytes of " + name);
        }

        const auto& bytes = *mem;
        duint ssn = 0;
        bool found = false;

        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
            uint32_t imm = 0;
            std::memcpy(&imm, &bytes[4], 4);
            ssn = static_cast<duint>(imm);
            found = true;
        } else if (bytes[0] == 0xB8) {
            uint32_t imm = 0;
            std::memcpy(&imm, &bytes[1], 4);
            ssn = static_cast<duint>(imm);
            found = true;
        }

        if (!found) {
            return s_http_response::ok({
                {"name",          name},
                {"address",       format_utils::format_address(fn_addr)},
                {"found",         false},
                {"syscall_id",    "N/A"},
                {"first_bytes",   format_utils::format_bytes_hex(bytes.data(), std::min<size_t>(bytes.size(), 8))}
            });
        }

        return s_http_response::ok({
            {"name",          name},
            {"address",       format_utils::format_address(fn_addr)},
            {"found",         true},
            {"syscall_id",    format_utils::format_address(ssn)},
            {"syscall_id_dec", ssn},
            {"first_bytes",   format_utils::format_bytes_hex(bytes.data(), std::min<size_t>(bytes.size(), 8))}
        });
    });

    router.get("/api/syscalls/hooks", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto ntdll_base = bridge.get_module_base("ntdll");
        if (ntdll_base == 0) {
            return s_http_response::not_found("ntdll not loaded");
        }

        auto hooked = nlohmann::json::array();

        for (int i = 0; i < 512; ++i) {
            auto fn_name = bridge.eval_expression("mod.exopa(ntdll, " + std::to_string(i) + ")");
            if (fn_name == 0) break;

            std::string fn_str = std::to_string(fn_name);
            auto fn_addr = bridge.eval_expression("ntdll." + fn_str);
            if (fn_addr == 0 || fn_addr < ntdll_base) continue;

            auto mem = bridge.read_memory(fn_addr, 16);
            if (!mem.has_value() || mem->size() < 5) continue;

            const auto& bytes = *mem;
            bool is_hooked = false;
            std::string hook_type = "clean";
            std::string expected = "4C 8B D1 B8 XX XX XX XX";

            if (bytes[0] == 0xFF && bytes[1] == 0x25) {
                is_hooked = true;
                hook_type = "inline_jmp";
            } else if (bytes[0] == 0xCC) {
                is_hooked = true;
                hook_type = "int3";
            } else if (bytes.size() >= 6 && bytes[0] == 0xE9) {
                is_hooked = true;
                hook_type = "inline_jmp";
            } else if (!(bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8)) {
                is_hooked = true;
                hook_type = "patch";
            }

            if (is_hooked) {
                std::string actual = format_utils::format_bytes_hex(bytes.data(), std::min<size_t>(bytes.size(), 5));
                hooked.push_back({
                    {"name",          fn_str},
                    {"address",       format_utils::format_address(fn_addr)},
                    {"is_hooked",     true},
                    {"first_bytes",   actual},
                    {"expected_bytes", expected},
                    {"hook_type",     hook_type}
                });
            }
        }

        return s_http_response::ok({
            {"module",  "ntdll"},
            {"base",    format_utils::format_address(ntdll_base)},
            {"hooked_count", hooked.size()},
            {"hooks",   hooked}
        });
    });

    router.get("/api/syscalls/kernel32", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto kernel32_base = bridge.get_module_base("kernel32");
        if (kernel32_base == 0) {
            return s_http_response::not_found("kernel32 not loaded");
        }

        auto hooked = nlohmann::json::array();

        for (int i = 0; i < 512; ++i) {
            auto fn_name = bridge.eval_expression("mod.exopa(kernel32, " + std::to_string(i) + ")");
            if (fn_name == 0) break;

            std::string fn_str = std::to_string(fn_name);
            auto fn_addr = bridge.eval_expression("kernel32." + fn_str);
            if (fn_addr == 0 || fn_addr < kernel32_base) continue;

            auto mem = bridge.read_memory(fn_addr, 16);
            if (!mem.has_value() || mem->size() < 2) continue;

            const auto& bytes = *mem;
            bool is_hooked = false;
            std::string hook_type = "clean";

            if (bytes[0] == 0xFF && bytes[1] == 0x25) {
                is_hooked = true;
                hook_type = "inline_jmp";
            } else if (bytes[0] == 0xCC) {
                is_hooked = true;
                hook_type = "int3";
            } else if (bytes.size() >= 6 && bytes[0] == 0xE9) {
                is_hooked = true;
                hook_type = "inline_jmp";
            }

            if (is_hooked) {
                std::string first = format_utils::format_bytes_hex(bytes.data(), std::min<size_t>(bytes.size(), 8));
                hooked.push_back({
                    {"name",        fn_str},
                    {"address",     format_utils::format_address(fn_addr)},
                    {"is_hooked",   true},
                    {"first_bytes", first},
                    {"hook_type",   hook_type}
                });
            }
        }

        return s_http_response::ok({
            {"module",      "kernel32"},
            {"base",        format_utils::format_address(kernel32_base)},
            {"hooked_count", hooked.size()},
            {"hooks",       hooked}
        });
    });
}

} // namespace handlers
