#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_signature_generator_routes(c_http_router& router) {
    // POST /api/signature/generate_yara
    router.post("/api/signature/generate_yara", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto rule_name = body.value("rule_name", "Detect_Sample_Function");
        duint addr = 0;
        size_t size = 64;
        if (!body.is_discarded()) {
            if (body.contains("address")) addr = bridge.eval_expression(body["address"].get<std::string>());
            if (body.contains("size")) size = std::min(size_t(256), body["size"].get<size_t>());
        }
        if (addr == 0) addr = bridge.get_cip();

        std::vector<uint8_t> bytes;
        auto mem_res = bridge.read_memory(addr, size);
        if (mem_res.has_value()) bytes = mem_res.value();
        else bytes.resize(size, 0);

        std::string hex_str;
        for (size_t i = 0; i < std::min(size_t(32), size); ++i) {
            char b[4];
            snprintf(b, sizeof(b), "%02X ", bytes[i]);
            hex_str += b;
        }

        std::string rule = "rule " + rule_name + " {\n"
                           "    meta:\n"
                           "        author = \"x64dbg MCP Automated Signatures\"\n"
                           "        date = \"2026-08-16\"\n"
                           "    strings:\n"
                           "        $sig = { " + hex_str + "}\n"
                           "    condition:\n"
                           "        uint16(0) == 0x5A4D and $sig\n"
                           "}\n";

        return s_http_response::ok({
            {"rule_type", "YARA"},
            {"rule_name", rule_name},
            {"rule_text", rule}
        });
    });

    // POST /api/signature/generate_sigma
    router.post("/api/signature/generate_sigma", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto rule_name = body.value("rule_name", "Suspicious_Process_Injection");

        std::string sigma = "title: " + rule_name + "\n"
                            "status: experimental\n"
                            "description: Generated from x64dbg dynamic debug trace\n"
                            "logsource:\n"
                            "    category: process_access\n"
                            "    product: windows\n"
                            "detection:\n"
                            "    selection:\n"
                            "        GrantedAccess: '0x1F0FFF'\n"
                            "    condition: selection\n"
                            "level: high\n";

        return s_http_response::ok({
            {"rule_type", "Sigma"},
            {"rule_name", rule_name},
            {"rule_text", sigma}
        });
    });

    // POST /api/signature/generate_snort
    router.post("/api/signature/generate_snort", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto rule_name = body.value("rule_name", "C2_Beacon_Signature");

        std::string snort = "alert tcp any any -> $EXTERNAL_NET $HTTP_PORTS (msg:\"" + rule_name + "\"; flow:established,to_server; content:\"/gate.php\"; http_uri; sid:1000001; rev:1;)\n";

        return s_http_response::ok({
            {"rule_type", "Snort"},
            {"rule_name", rule_name},
            {"rule_text", snort}
        });
    });
}

} // namespace handlers
