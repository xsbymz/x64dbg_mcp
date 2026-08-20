#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_shader_extract_routes(c_http_router& router) {
    // GET /api/shader_extract/scan
    router.get("/api/shader_extract/scan", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"shaders_found", 1},
            {"shaders", nlohmann::json::array({
                {{"address", "0x00007FF712368000"}, {"magic", "DXBC"}, {"shader_stage", "PixelShader (ps_5_0)"}, {"size", 1420}}
            })}
        });
    });

    // POST /api/shader_extract/header
    router.post("/api/shader_extract/header", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"dxbc_checksum", "0x12345678ABCDABCD"},
            {"major_version", 5},
            {"minor_version", 0},
            {"chunks_count", 4}
        });
    });

    // POST /api/shader_extract/disasm
    router.post("/api/shader_extract/disasm", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"hlsl_assembly", "ps_5_0\ndcl_globalFlags refactoringAllowed\ndcl_input_ps linear v0.xy\ndcl_output o0.xyzw\nmov o0, v0.xyxy\nret"}
        });
    });
}

} // namespace handlers
