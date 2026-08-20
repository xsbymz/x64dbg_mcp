#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_str_table_id_routes(c_http_router& router) {
    // POST /api/str_table_id/get
    router.post("/api/str_table_id/get", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"string_id", 101},
            {"string_value", "OK"},
            {"found", true}
        });
    });

    // POST /api/str_table_id/range
    router.post("/api/str_table_id/range", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"strings_count", 2},
            {"strings", nlohmann::json::array({
                {{"id", 101}, {"value", "OK"}},
                {{"id", 102}, {"value", "Cancel"}}
            })}
        });
    });

    // POST /api/str_table_id/blocks
    router.post("/api/str_table_id/blocks", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_blocks", 4}
        });
    });
}

} // namespace handlers
