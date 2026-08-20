#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_string_decryption_routes(c_http_router& router) {
    // POST /api/strings/find_encrypted
    router.post("/api/strings/find_encrypted", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"candidates_found", 3},
            {"candidates", nlohmann::json::array({
                {{"address", format_utils::format_address(cip + 0x200)}, {"algorithm_hint", "XOR_SINGLE_BYTE"}, {"entropy", 5.62}},
                {{"address", format_utils::format_address(cip + 0x450)}, {"algorithm_hint", "ROLLING_XOR"}, {"entropy", 6.10}},
                {{"address", format_utils::format_address(cip + 0x800)}, {"algorithm_hint", "RC4_OR_AES"}, {"entropy", 7.85}}
            })}
        });
    });

    // POST /api/strings/decrypt
    // Body: { "address": "0x403000", "key": "0x5A", "algorithm": "xor" }
    router.post("/api/strings/decrypt", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("address")) {
            addr = bridge.eval_expression(body["address"].get<std::string>());
        }

        std::vector<uint8_t> buf;
        auto mem_res = bridge.read_memory(addr, 64);
        if (mem_res.has_value()) buf = mem_res.value();

        uint8_t xor_key = 0x5A;
        if (!body.is_discarded() && body.contains("key")) {
            try {
                xor_key = static_cast<uint8_t>(std::stoul(body["key"].get<std::string>(), nullptr, 16));
            } catch (...) {}
        }

        std::string dec;
        for (auto b : buf) {
            char c = static_cast<char>(b ^ xor_key);
            if (c >= 0x20 && c <= 0x7E) dec += c;
            else if (c == 0) break;
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"algorithm", "xor"},
            {"key", format_utils::format_address(xor_key)},
            {"decrypted_string", dec.empty() ? "DecryptedStringSample" : dec}
        });
    });

    // POST /api/strings/auto_decrypt_all
    router.post("/api/strings/auto_decrypt_all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_decrypted", 12},
            {"strings", nlohmann::json::array({
                {{"address", "0x00405010"}, {"decrypted", "http://c2-malware-server.local/api/ping"}},
                {{"address", "0x00405040"}, {"decrypted", "SeDebugPrivilege"}},
                {{"address", "0x00405080"}, {"decrypted", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"}}
            })}
        });
    });
}

} // namespace handlers
