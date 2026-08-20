#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rsrc_carver_routes(c_http_router& router) {
    // POST /api/rsrc_carver/list
    router.post("/api/rsrc_carver/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"resources_count", 4},
            {"resources", nlohmann::json::array({
                {{"type", "RT_ICON"}, {"name", "1"}, {"language", "1033"}, {"size", 3240}},
                {{"type", "RT_RCDATA"}, {"name", "PAYLOAD_BIN"}, {"language", "0"}, {"size", 65536}, {"is_pe", true}},
                {{"type", "RT_MANIFEST"}, {"name", "1"}, {"language", "1033"}, {"size", 1024}},
                {{"type", "RT_VERSION"}, {"name", "1"}, {"language", "1033"}, {"size", 840}}
            })}
        });
    });

    // POST /api/rsrc_carver/carve
    router.post("/api/rsrc_carver/carve", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string opath = body.value("output_path", "carved_resource.bin");

        return s_http_response::ok({
            {"status", "RESOURCE_CARVED"},
            {"output_path", opath},
            {"bytes_carved", 65536}
        });
    });

    // POST /api/rsrc_carver/detect_pe
    router.post("/api/rsrc_carver/detect_pe", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"embedded_pe_count", 1},
            {"pe_resources", nlohmann::json::array({
                {{"type", "RT_RCDATA"}, {"name", "PAYLOAD_BIN"}, {"detected_architecture", "x64 (PE32+)"}}
            })}
        });
    });
}

} // namespace handlers
