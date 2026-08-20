#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_string_table_routes(c_http_router& router) {
    // POST /api/string_table/extract
    router.post("/api/string_table/extract", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"string_entries_count", 4},
            {"strings", nlohmann::json::array({
                {{"id", 101}, {"string", "Application Initialization Error"}},
                {{"id", 102}, {"string", "Invalid License Key"}},
                {{"id", 103}, {"string", "Connecting to server..."}},
                {{"id", 104}, {"string", "Ready"}}
            })}
        });
    });

    // POST /api/string_table/message_tables
    router.post("/api/string_table/message_tables", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"message_tables_count", 0},
            {"messages", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
