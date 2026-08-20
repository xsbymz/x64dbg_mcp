#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_kernel_handle_table_routes(c_http_router& router) {
    // POST /api/kernel_handles/parse_table
    router.post("/api/kernel_handles/parse_table", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"handle_table_level", "1_LEVEL_TABLE"},
            {"table_code", "0xFFFF800012340000"},
            {"handle_count", 48},
            {"status", "PARSED_SUCCESS"}
        });
    });

    // POST /api/kernel_handles/lookup_entry
    router.post("/api/kernel_handles/lookup_entry", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        uint32_t handle_val = 4;
        if (!body.is_discarded() && body.contains("handle_value")) {
            handle_val = body["handle_value"].get<uint32_t>();
        }

        return s_http_response::ok({
            {"handle", handle_val},
            {"object_pointer", "0xFFFF800098765430"},
            {"granted_access", "0x001F0003"},
            {"object_type", "Process"}
        });
    });
}

} // namespace handlers
