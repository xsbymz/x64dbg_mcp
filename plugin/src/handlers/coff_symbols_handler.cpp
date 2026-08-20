#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_coff_symbols_routes(c_http_router& router) {
    // POST /api/coff_symbols/parse
    router.post("/api/coff_symbols/parse", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"has_coff_symbols", false},
            {"symbol_count", 0},
            {"symbols", nlohmann::json::array()}
        });
    });

    // POST /api/coff_symbols/strings
    router.post("/api/coff_symbols/strings", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"string_table_size", 0}
        });
    });

    // POST /api/coff_symbols/count
    router.post("/api/coff_symbols/count", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"symbols_count", 0}
        });
    });
}

} // namespace handlers
