#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_clr_domain_routes(c_http_router& router) {
    // GET /api/clr_domain/list
    router.get("/api/clr_domain/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"appdomains_count", 1},
            {"domains", nlohmann::json::array({
                {{"id", 1}, {"name", "DefaultDomain"}, {"stage", "STAGE_ACTIVE"}}
            })}
        });
    });

    // POST /api/clr_domain/loader_heaps
    router.post("/api/clr_domain/loader_heaps", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"high_frequency_heap_size", 0x10000},
            {"low_frequency_heap_size", 0x8000},
            {"stub_heap_size", 0x4000}
        });
    });

    // POST /api/clr_domain/assemblies
    router.post("/api/clr_domain/assemblies", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"assemblies", nlohmann::json::array({
                "System.Private.CoreLib.dll",
                "TargetApplication.dll"
            })}
        });
    });
}

} // namespace handlers
