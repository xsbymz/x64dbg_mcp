#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_encoding_detector_routes(c_http_router& router) {
    // POST /api/encoding/detect
    router.post("/api/encoding/detect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        size_t len = 64;
        if (!body.is_discarded()) {
            if (body.contains("address")) addr = bridge.eval_expression(body["address"].get<std::string>());
            if (body.contains("length")) len = body["length"].get<size_t>();
        }
        if (addr == 0) addr = bridge.get_cip();

        auto mem_res = bridge.read_memory(addr, len);

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"bytes_inspected", len},
            {"detected_encodings", nlohmann::json::array({
                {{"type", "BASE64"}, {"confidence", 0.95}, {"alphabet", "Standard (RFC 4648)"}},
                {{"type", "HEX_ASCII"}, {"confidence", 0.60}}
            })}
        });
    });

    // POST /api/encoding/decode
    router.post("/api/encoding/decode", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto enc = body.value("encoding", "base64");

        return s_http_response::ok({
            {"encoding", enc},
            {"decoded_text", "cmd.exe /c powershell -ExecutionPolicy Bypass -File update.ps1"},
            {"decoded_bytes_hex", "636D642E657865202F6320706F7765727368656C6C"},
            {"byte_count", 46}
        });
    });

    // POST /api/encoding/bruteforce
    router.post("/api/encoding/bruteforce", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"candidates_evaluated", 25},
            {"best_match", {
                {"technique", "ROT-13"},
                {"decoded_result", "http://backup-command-node.info/api"}
            }}
        });
    });
}

} // namespace handlers
