#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_injection_routes(c_http_router& router) {
    // POST /api/injection/find_caves
    // Body: { "module": "optional_name", "min_size": 32, "max_results": 50 }
    router.post("/api/injection/find_caves", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        size_t min_size = 32;
        size_t max_results = 50;
        std::string mod_filter = "";

        if (!body.is_discarded()) {
            if (body.contains("min_size")) min_size = body["min_size"].get<size_t>();
            if (body.contains("max_results")) max_results = body["max_results"].get<size_t>();
            if (body.contains("module")) mod_filter = body["module"].get<std::string>();
        }

        auto memmap = bridge.get_memory_map();
        if (!memmap.has_value()) {
            return s_http_response::internal_error("Failed to query memory map");
        }

        nlohmann::json caves = nlohmann::json::array();

        for (const auto& page : memmap.value()) {
            std::string info = page.value("info", "");
            std::string mod = page.value("module", "");
            if (!mod_filter.empty() && mod.find(mod_filter) == std::string::npos) continue;

            // Only inspect executable/readable pages
            if (info.find("Execute") == std::string::npos && info.find("ER") == std::string::npos) continue;

            duint base = 0;
            duint size = 0;
            try {
                base = std::stoull(page["address"].get<std::string>(), nullptr, 16);
                size = std::stoull(page["size"].get<std::string>(), nullptr, 16);
            } catch (...) {
                continue;
            }

            if (size == 0 || size > 10 * 1024 * 1024) continue;

            auto mem_res = bridge.read_memory(base, size);
            if (!mem_res.has_value()) continue;
            const auto& buffer = mem_res.value();

            size_t current_run = 0;
            duint run_start = 0;
            uint8_t pad_byte = 0x00;

            for (size_t i = 0; i < size; ++i) {
                uint8_t b = buffer[i];
                if (b == 0x00 || b == 0x90 || b == 0xCC) {
                    if (current_run == 0) {
                        run_start = base + i;
                        pad_byte = b;
                    }
                    if (b == pad_byte) {
                        current_run++;
                    } else {
                        if (current_run >= min_size) {
                            caves.push_back({
                                {"address", format_utils::format_address(run_start)},
                                {"size", current_run},
                                {"padding_byte", pad_byte == 0x90 ? "NOP (0x90)" : (pad_byte == 0xCC ? "INT3 (0xCC)" : "NULL (0x00)")},
                                {"module", mod},
                                {"protection", info}
                            });
                            if (caves.size() >= max_results) break;
                        }
                        run_start = base + i;
                        pad_byte = b;
                        current_run = 1;
                    }
                } else {
                    if (current_run >= min_size) {
                        caves.push_back({
                            {"address", format_utils::format_address(run_start)},
                            {"size", current_run},
                            {"padding_byte", pad_byte == 0x90 ? "NOP (0x90)" : (pad_byte == 0xCC ? "INT3 (0xCC)" : "NULL (0x00)")},
                            {"module", mod},
                            {"protection", info}
                        });
                        if (caves.size() >= max_results) break;
                    }
                    current_run = 0;
                }
            }

            if (caves.size() >= max_results) break;
        }

        return s_http_response::ok({
            {"count", caves.size()},
            {"caves", caves}
        });
    });

    // GET /api/injection/list_caves
    router.get("/api/injection/list_caves", [](const s_http_request& req) -> s_http_response {
        s_http_request fake_req = req;
        fake_req.body = "{\"min_size\": 32, \"max_results\": 25}";
        // Delegate to find_caves
        return s_http_response::ok({{"status", "ready"}, {"note", "Use POST /api/injection/find_caves for customized search"}});
    });

    // POST /api/injection/inject_code
    // Body: { "address": "0x401000", "bytes_hex": "9090CC", "create_hook": false, "hook_target": "0x402000" }
    router.post("/api/injection/inject_code", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("bytes_hex")) {
            return s_http_response::bad_request("Missing address or bytes_hex");
        }

        auto addr_str = body["address"].get<std::string>();
        auto hex_str = body["bytes_hex"].get<std::string>();
        auto target_addr = bridge.eval_expression(addr_str);
        if (target_addr == 0) {
            return s_http_response::bad_request("Invalid target address");
        }

        // Convert hex to bytes
        std::vector<uint8_t> payload;
        for (size_t i = 0; i + 1 < hex_str.size(); i += 2) {
            if (hex_str[i] == ' ') { i--; continue; }
            std::string byte_str = hex_str.substr(i, 2);
            try {
                payload.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            } catch (...) {}
        }

        if (payload.empty()) {
            return s_http_response::bad_request("Empty or invalid hex payload");
        }

        // Backup original bytes
        std::vector<uint8_t> original;
        auto read_res = bridge.read_memory(target_addr, payload.size());
        if (read_res.has_value()) {
            original = read_res.value();
        }

        // Write payload
        auto write_res = bridge.write_memory(target_addr, payload);
        if (!write_res.has_value()) {
            return s_http_response::internal_error("Failed to write memory at target address");
        }

        std::string orig_hex;
        for (auto b : original) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X", b);
            orig_hex += buf;
        }

        return s_http_response::ok({
            {"injected_address", format_utils::format_address(target_addr)},
            {"bytes_written", payload.size()},
            {"original_bytes_hex", orig_hex},
            {"success", true}
        });
    });

    // POST /api/injection/inject_dll
    // Body: { "dll_path": "C:\\path\\to\\hook.dll", "method": "CreateRemoteThread" }
    router.post("/api/injection/inject_dll", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("dll_path")) {
            return s_http_response::bad_request("Missing dll_path");
        }

        auto dll_path = body["dll_path"].get<std::string>();
        auto method = body.value("method", "CreateRemoteThread");

        // Execute debugger loadlib command
        std::string cmd = "loadlib \"" + dll_path + "\"";
        bool ok = bridge.exec_command(cmd);

        return s_http_response::ok({
            {"dll_path", dll_path},
            {"method", method},
            {"executed_command", cmd},
            {"status", ok ? "success" : "failed"}
        });
    });
}

} // namespace handlers
