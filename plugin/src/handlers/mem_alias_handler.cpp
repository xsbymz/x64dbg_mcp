#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_mem_alias_routes(c_http_router& router) {
    // POST /api/mem_alias/scan
    router.post("/api/mem_alias/scan", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"aliased_regions_count", 1},
            {"aliased_regions", nlohmann::json::array({
                {{"source_address", "0x00007FF712340000"}, {"mirrored_address", "0x00007FF780000000"}, {"section_name", "\\Device\\HarddiskVolume3\\app.exe"}, {"cow_active", false}}
            })}
        });
    });

    // GET /api/mem_alias/section_views
    router.get("/api/mem_alias/section_views", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"section_views_count", 4},
            {"views", nlohmann::json::array({
                {{"base_address", "0x00007FF712340000"}, {"view_size", 0x20000}, {"allocation_type", "SEC_IMAGE"}}
            })}
        });
    });

    // POST /api/mem_alias/cow_pages
    router.post("/api/mem_alias/cow_pages", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"cow_pages_modified_count", 0},
            {"has_private_writes", false}
        });
    });
}

} // namespace handlers
