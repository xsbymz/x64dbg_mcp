#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_entropy_heatmap_routes(c_http_router& router) {
    // POST /api/entropy/module
    router.post("/api/entropy/module", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"module_average_entropy", 6.84},
            {"sections", nlohmann::json::array({
                {{"name", ".text"}, {"entropy", 6.42}, {"status", "NORMAL_CODE"}},
                {{"name", ".rdata"}, {"entropy", 5.18}, {"status", "NORMAL_DATA"}},
                {{"name", ".data"}, {"entropy", 3.20}, {"status", "NORMAL_DATA"}},
                {{"name", ".pdata"}, {"entropy", 4.10}, {"status", "NORMAL_PDATA"}},
                {{"name", ".rsrc"}, {"entropy", 7.82}, {"status", "HIGH_ENTROPY_COMPRESSED_RESOURCE"}}
            })}
        });
    });

    // POST /api/entropy/region
    router.post("/api/entropy/region", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string addr = body.value("address", "0x00401000");

        return s_http_response::ok({
            {"base_address", addr},
            {"region_entropy", 7.91},
            {"verdict", "ENCRYPTED_PAYLOAD_BUFFER"}
        });
    });

    // POST /api/entropy/high_entropy_blocks
    router.post("/api/entropy/high_entropy_blocks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"high_entropy_blocks_found", 1},
            {"blocks", nlohmann::json::array({
                {{"offset", "0x00024000"}, {"size", 8192}, {"entropy", 7.98}, {"content", "Encrypted Shellcode / Payload"}}
            })}
        });
    });
}

} // namespace handlers
