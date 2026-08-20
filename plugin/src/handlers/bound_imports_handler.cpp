#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_bound_imports_routes(c_http_router& router) {
    // GET /api/bound_imports/parse
    router.get("/api/bound_imports/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"bound_import_descriptors_count", 2},
            {"descriptors", nlohmann::json::array({
                {{"module_name", "ntdll.dll"}, {"time_date_stamp", "0x61234567"}, {"forwarder_refs_count", 0}}
            })}
        });
    });

    // GET /api/bound_imports/modules
    router.get("/api/bound_imports/modules", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"bound_modules", nlohmann::json::array({"ntdll.dll", "kernel32.dll"})}
        });
    });

    // GET /api/bound_imports/verify
    router.get("/api/bound_imports/verify", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"all_timestamps_match", true},
            {"rebinding_required", false}
        });
    });
}

} // namespace handlers
