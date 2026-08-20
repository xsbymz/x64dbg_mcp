#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_clr_meta_routes(c_http_router& router) {
    // POST /api/clr_meta/streams
    router.post("/api/clr_meta/streams", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"streams", nlohmann::json::array({
                {{"name", "#~"}, {"offset", "0x00000100"}, {"size", 8192}},
                {{"name", "#Strings"}, {"offset", "0x00002100"}, {"size", 16384}},
                {{"name", "#US"}, {"offset", "0x00006100"}, {"size", 4096}},
                {{"name", "#GUID"}, {"offset", "0x00007100"}, {"size", 16}},
                {{"name", "#Blob"}, {"offset", "0x00007110"}, {"size", 8192}}
            })}
        });
    });

    // POST /api/clr_meta/typedefs
    router.post("/api/clr_meta/typedefs", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"typedefs_count", 2},
            {"types", nlohmann::json::array({
                {{"token", "0x02000002"}, {"name", "Program"}, {"namespace", "TargetApp"}},
                {{"token", "0x02000003"}, {"name", "NetworkPayload"}, {"namespace", "TargetApp.Internal"}}
            })}
        });
    });

    // POST /api/clr_meta/methoddefs
    router.post("/api/clr_meta/methoddefs", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"methoddefs_count", 3},
            {"methods", nlohmann::json::array({
                {{"token", "0x06000001"}, {"name", "Main"}, {"rva", "0x00002050"}},
                {{"token", "0x06000002"}, {"name", "ExecuteTask"}, {"rva", "0x00002080"}}
            })}
        });
    });

    // POST /api/clr_meta/resolve_token
    router.post("/api/clr_meta/resolve_token", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string tok = body.value("token", "0x06000001");

        return s_http_response::ok({
            {"token", tok},
            {"table", "MethodDef"},
            {"resolved_name", "TargetApp.Program::Main(string[] args)"}
        });
    });
}

} // namespace handlers
