#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cfg_guard_routes(c_http_router& router) {
    // POST /api/cfg_guard/check_address
    router.post("/api/cfg_guard/check_address", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string addr = body.value("address", "0x00007FF712341000");

        return s_http_response::ok({
            {"address", addr},
            {"is_valid_cfg_target", true},
            {"is_suppressed", false}
        });
    });

    // POST /api/cfg_guard/dump_table
    router.post("/api/cfg_guard/dump_table", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"valid_targets_count", 482},
            {"table_rva", "0x00018000"}
        });
    });

    // POST /api/cfg_guard/bitmap_state
    router.post("/api/cfg_guard/bitmap_state", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"bitmap_bit_value", 1},
            {"bitmap_page_address", "0x00007FFF80000000"}
        });
    });
}

} // namespace handlers
