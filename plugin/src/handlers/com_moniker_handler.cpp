#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_com_moniker_routes(c_http_router& router) {
    // POST /api/com_moniker/parse
    router.post("/api/com_moniker/parse", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string name = body.value("display_name", "clsid:00000000-0000-0000-0000-000000000000");

        return s_http_response::ok({
            {"display_name", name},
            {"moniker_type", "ClassMoniker"},
            {"target_clsid", "{00000000-0000-0000-0000-000000000000}"}
        });
    });

    // GET /api/com_moniker/registered
    router.get("/api/com_moniker/registered", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registered_monikers_count", 0},
            {"monikers", nlohmann::json::array()}
        });
    });

    // GET /api/com_moniker/rot
    router.get("/api/com_moniker/rot", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"running_object_table_entries", 0}
        });
    });
}

} // namespace handlers
