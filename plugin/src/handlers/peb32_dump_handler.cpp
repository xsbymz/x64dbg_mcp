#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_peb32_dump_routes(c_http_router& router) {
    // GET /api/peb32_dump/peb
    router.get("/api/peb32_dump/peb", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"peb32_address", "0x00410000"},
            {"being_debugged", 1},
            {"image_base_address", "0x00400000"}
        });
    });

    // GET /api/peb32_dump/params
    router.get("/api/peb32_dump/params", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"command_line", "\"C:\\target32.exe\""},
            {"image_path", "C:\\target32.exe"}
        });
    });

    // GET /api/peb32_dump/modules
    router.get("/api/peb32_dump/modules", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"modules_count", 4},
            {"modules", nlohmann::json::array({
                {{"name", "target32.exe"}, {"base", "0x00400000"}},
                {{"name", "ntdll32.dll"}, {"base", "0x77300000"}}
            })}
        });
    });
}

} // namespace handlers
