#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pe_cor20_routes(c_http_router& router) {
    // GET /api/pe_cor20/header
    router.get("/api/pe_cor20/header", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"cor20_header_present", true},
            {"major_runtime_version", 2},
            {"minor_runtime_version", 5},
            {"flags", "COMIMAGE_FLAGS_ILONLY (0x01)"},
            {"entry_point_token", "0x06000001"}
        });
    });

    // GET /api/pe_cor20/vtable_fixups
    router.get("/api/pe_cor20/vtable_fixups", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"vtable_fixups_count", 0},
            {"fixups", nlohmann::json::array()}
        });
    });

    // GET /api/pe_cor20/strong_name
    router.get("/api/pe_cor20/strong_name", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_strong_name_signed", true},
            {"public_key_token", "b03f5f7f11d50a3a"}
        });
    });
}

} // namespace handlers
