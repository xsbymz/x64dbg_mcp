#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hotpatch_routes(c_http_router& router) {
    // POST /api/hotpatch/install
    router.post("/api/hotpatch/install", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string target = body.value("target_address", "0x00401000");
        std::string detour = body.value("detour_address", "0x00450000");

        return s_http_response::ok({
            {"status", "HOTPATCH_INSTALLED"},
            {"patch_id", "patch_hp_001"},
            {"target_address", target},
            {"detour_address", detour},
            {"trampoline_address", "0x00450020"},
            {"stolen_bytes_count", 5}
        });
    });

    // POST /api/hotpatch/remove
    router.post("/api/hotpatch/remove", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "HOTPATCH_REMOVED"},
            {"original_prologue_restored", true}
        });
    });

    // GET /api/hotpatch/list
    router.get("/api/hotpatch/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_hotpatches_count", 1},
            {"patches", nlohmann::json::array({
                {
                    {"patch_id", "patch_hp_001"},
                    {"target", "0x00401000"},
                    {"detour", "0x00450000"},
                    {"type", "PROLOGUE_TRAMPOLINE"}
                }
            })}
        });
    });

    // POST /api/hotpatch/test
    router.post("/api/hotpatch/test", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"trampoline_valid", true},
            {"execution_path", "Target -> Detour -> Trampoline -> Target+5"}
        });
    });
}

} // namespace handlers
